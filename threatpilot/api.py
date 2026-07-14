from fastapi import FastAPI, HTTPException
from typing import List, Dict
from pydantic import BaseModel

from threatpilot.core.v2_models import Threat, ThreatContext
from threatpilot.core.threat_db import ThreatDatabase
from threatpilot.engine.graph import ArchitectureGraph, Node, Edge
from threatpilot.engine.traversal import TraversalEngine

app = FastAPI(
    title="ThreatPilot API", 
    version="1.0.0",
    description="REST API for executing ThreatPilot runs and querying the Threat Database."
)

# In-memory database instance for the API
db = ThreatDatabase()

class RunAnalysisRequest(BaseModel):
    nodes: List[Node]
    edges: List[Edge]
    entry_nodes: List[str]
    initial_contexts: Dict[str, ThreatContext]

@app.post("/analyze")
def run_analysis(request: RunAnalysisRequest):
    """
    Trigger a full threat modeling run from a JSON architecture definition.
    This is ideal for kicking off async analyses from external Web UIs or CI pipelines.
    """
    graph = ArchitectureGraph()
    for node in request.nodes:
        graph.add_node(node)
    for edge in request.edges:
        graph.add_edge(edge)
        
    engine = TraversalEngine(graph)
    memory = engine.run_traversal(request.entry_nodes, request.initial_contexts)
    
    # NOTE: The AI Orchestrator would process the `memory` and `graph` here
    # and save results into `db`.
    
    return {
        "status": "success", 
        "message": "Graph traversal complete.",
        "events_logged": len(memory.events)
    }

@app.get("/threats", response_model=List[Threat])
def get_threats():
    """Retrieve all active threats from the database."""
    return list(db.all_threats.values())

@app.get("/threats/{threat_id}", response_model=Threat)
def get_threat(threat_id: str):
    """Retrieve a specific threat by its stable ID."""
    threat = db.all_threats.get(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat
