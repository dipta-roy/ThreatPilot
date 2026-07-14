from typing import List, Dict, Any, Optional
import heapq
from pydantic import BaseModel, Field

from threatpilot.core.v2_models import ThreatContext, AttackMemory, EventLogEntry
from threatpilot.engine.graph import ArchitectureGraph, Edge, Node

class TraversalQueueItem(BaseModel):
    risk_score: float
    edge_id: str
    current_context: ThreatContext
    
    # Enable sorting by risk_score (negative for max-heap behavior in heapq)
    def __lt__(self, other):
        return self.risk_score > other.risk_score

class TraversalEngine:
    def __init__(
        self, 
        graph: ArchitectureGraph,
        global_visited_edges: Optional[set] = None,
        global_node_contexts: Optional[Dict[str, List[ThreatContext]]] = None
    ):
        self.graph = graph
        self.priority_queue: List[TraversalQueueItem] = []
        self.visited_edges: set = global_visited_edges if global_visited_edges is not None else set()
        self.attack_memory = AttackMemory()
        # Multi-Path Convergence: accumulate contexts arriving at each node
        self._node_contexts: Dict[str, List[ThreatContext]] = global_node_contexts if global_node_contexts is not None else {}

    def _merge_converged_contexts(self, contexts: List[ThreatContext]) -> ThreatContext:
        """Merges multiple inbound contexts into a single combined threat surface.
        
        When multiple paths converge on a single node (e.g., A→B and D→B),
        this produces a worst-case composite context representing the combined attack surface.
        """
        if len(contexts) == 1:
            return contexts[0]
        
        base = contexts[0].model_copy(deep=True)
        for ctx in contexts[1:]:
            # Take the highest risk score
            if ctx.dynamic.risk_score > base.dynamic.risk_score:
                base.dynamic.risk_score = ctx.dynamic.risk_score
            # If any path is authenticated, preserve that
            if ctx.dynamic.authenticated:
                base.dynamic.authenticated = True
            # Merge tokens obtained from all paths
            for token in ctx.dynamic.tokens_obtained:
                if token not in base.dynamic.tokens_obtained:
                    base.dynamic.tokens_obtained.append(token)
            # Take highest privilege level
            privilege_order = ["None", "User", "Operator", "Admin", "Root"]
            base_idx = privilege_order.index(base.dynamic.current_privileges) if base.dynamic.current_privileges in privilege_order else 0
            ctx_idx = privilege_order.index(ctx.dynamic.current_privileges) if ctx.dynamic.current_privileges in privilege_order else 0
            if ctx_idx > base_idx:
                base.dynamic.current_privileges = ctx.dynamic.current_privileges
        return base
        
    def calculate_edge_risk(self, edge: Edge, source_node: Node, target_node: Node, context: ThreatContext) -> float:
        """
        Risk = External Exposure + Trust Boundary + Sensitive Data + 
               Internet Reachability + Business Criticality + Authentication State
        """
        score = 0.0
        
        # 1. External Exposure
        if source_node.trust_zone == "Internet" or source_node.metadata.internet_facing:
            score += 10.0
            
        # 2. Trust Boundary crossing
        if source_node.trust_zone != target_node.trust_zone:
            score += 5.0
            
        # 3. Sensitive Data
        if "PII" in edge.data_flow_types or target_node.metadata.contains_pii:
            score += 8.0
        if "Credentials" in edge.data_flow_types:
            score += 9.0
            
        # 4. Authentication State
        if not context.dynamic.authenticated and target_node.trust_zone != "Public":
            score += 7.0  # High risk if unauthenticated traffic hits an internal node
            
        return score

    def mutate_context(self, edge: Edge, source: Node, target: Node, context: ThreatContext) -> ThreatContext:
        """Apply deterministic rules to mutate ThreatContext across an edge."""
        # Deep copy to ensure immutable propagation
        new_context = context.model_copy(deep=True)
        
        # Example Mutation Rule 1: Auth Service Grants Authentication
        if target.type == "AuthenticationService":
            new_context.dynamic.authenticated = True
            
        # Example Mutation Rule 2: Crossing Trust Boundaries
        if source.trust_zone != target.trust_zone:
            # We crossed a boundary, record the event
            self.attack_memory.add_event(
                description=f"Crossed trust boundary from {source.trust_zone} to {target.trust_zone}",
                node_id=target.id,
                edge_id=edge.id,
                context=new_context
            )
            
        # Example Mutation Rule 3: Assuming TLS if out of scope / third party
        if target.trust_zone == "External SaaS" or target.type == "ThirdPartyAPI":
            # Assumption Recording
            self.attack_memory.add_event(
                description=f"Out of scope element reached: {target.name}. Assuming TLS and vendor-managed controls.",
                node_id=target.id,
                edge_id=edge.id,
                context=new_context
            )
            
        return new_context

    def enqueue_edge(self, edge: Edge, context: ThreatContext):
        source = self.graph.get_node(edge.source_id)
        target = self.graph.get_node(edge.target_id)
        if not source or not target:
            return
            
        risk_score = self.calculate_edge_risk(edge, source, target, context)
        item = TraversalQueueItem(risk_score=risk_score, edge_id=edge.id, current_context=context)
        heapq.heappush(self.priority_queue, item)

    def _get_downstream_nodes(self, start_node_ids: List[str]) -> set:
        visited = set(start_node_ids)
        queue = list(start_node_ids)
        while queue:
            curr = queue.pop(0)
            edges = self.graph.get_outbound_edges(curr)
            for e in edges:
                if e.target_id not in visited:
                    visited.add(e.target_id)
                    queue.append(e.target_id)
        return visited

    def run_traversal(self, entry_nodes: List[str], initial_contexts: Dict[str, ThreatContext], changed_node_ids: Optional[List[str]] = None):
        """
        Start the traversal from designated entry points using a Risk-Driven Priority Queue.
        If changed_node_ids is provided, performs an incremental run evaluating only downstream impact.
        """
        affected_nodes = None
        if changed_node_ids:
            affected_nodes = self._get_downstream_nodes(changed_node_ids)
            
            # Mark affected nodes for reanalysis
            for node_id in affected_nodes:
                node = self.graph.get_node(node_id)
                if node and hasattr(node, "analysis_state"):
                    from threatpilot.engine.graph import NodeAnalysisState
                    node.analysis_state = NodeAnalysisState.NEEDS_REANALYSIS

        # Initialize queue from entry points
        for node_id in entry_nodes:
            context = initial_contexts.get(node_id)
            if not context:
                continue
            
            self.attack_memory.add_event(
                description=f"Initiated traversal at Entry Point: {node_id}",
                node_id=node_id,
                context=context
            )
                
            outbound_edges = self.graph.get_outbound_edges(node_id)
            for edge in outbound_edges:
                self.enqueue_edge(edge, context)
                
        # Process Priority Queue
        while self.priority_queue:
            item = heapq.heappop(self.priority_queue)
            
            if item.edge_id in self.visited_edges:
                continue
                
            self.visited_edges.add(item.edge_id)
            edge = next((e for e in self.graph.edges if e.id == item.edge_id), None)
            if not edge:
                continue
                
            source = self.graph.get_node(edge.source_id)
            target = self.graph.get_node(edge.target_id)
            
            # Mutate context across this edge
            new_context = self.mutate_context(edge, source, target, item.current_context)
            new_context.dynamic.risk_score = item.risk_score
            
            # Multi-Path Convergence: accumulate all inbound contexts for the target node
            if target.id not in self._node_contexts:
                self._node_contexts[target.id] = []
            self._node_contexts[target.id].append(new_context)
            
            # Merge all converged contexts into a combined threat surface
            merged_context = self._merge_converged_contexts(self._node_contexts[target.id])
            
            # In incremental mode, only analyze if in affected_nodes
            is_affected = affected_nodes is None or source.id in affected_nodes or target.id in affected_nodes
            
            if is_affected:
                if hasattr(target, "analysis_state"):
                    from threatpilot.engine.graph import NodeAnalysisState
                    target.analysis_state = NodeAnalysisState.ANALYZED
                
                if getattr(self, "ai_callback", None):
                    neighborhood = self.graph.get_neighborhood(edge.id)
                    self.ai_callback(neighborhood, merged_context, self.attack_memory)
                    
            elif hasattr(target, "analysis_state"):
                from threatpilot.engine.graph import NodeAnalysisState
                target.analysis_state = NodeAnalysisState.OUT_OF_SCOPE
            
            # Fan-out to downstream edges using the merged context
            downstream_edges = self.graph.get_outbound_edges(target.id)
            for down_edge in downstream_edges:
                if down_edge.id not in self.visited_edges:
                    self.enqueue_edge(down_edge, merged_context)
                    
        return self.attack_memory

