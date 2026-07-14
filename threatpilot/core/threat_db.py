from typing import List, Dict, Optional
import hashlib
from threatpilot.core.v2_models import Threat, ThreatState, ThreatCategory

class ThreatDatabase:
    """
    In-memory Threat Database that manages categorized storage, 
    stable identities, and lifecycle state machine transitions.
    """
    def __init__(self):
        # Categorized storage aligned with how engineers triage issues
        self.component_threats: Dict[str, Threat] = {}
        self.data_flow_threats: Dict[str, Threat] = {}
        self.attack_path_threats: Dict[str, Threat] = {}
        
        # Unified index
        self.all_threats: Dict[str, Threat] = {}
        
    def generate_stable_id(self, target_id: str, threat_title: str) -> str:
        """
        Generates a stable identity (e.g., TP-A4F29B) based on a deterministic signature.
        This ensures that running the traversal multiple times yields the same Threat ID.
        """
        signature = f"{target_id}::{threat_title}"
        hash_object = hashlib.sha256(signature.encode())
        hash_hex = hash_object.hexdigest()[:6].upper()
        return f"TP-{hash_hex}"
        
    def register_threat(self, threat: Threat):
        """Add or update a threat, routing it to the proper categorized storage."""
        if threat.id in self.all_threats:
            # The threat already exists. Transition state to EXISTING or UPDATED.
            existing_threat = self.all_threats[threat.id]
            if existing_threat.state == ThreatState.NEW:
                self.transition_state(threat.id, ThreatState.EXISTING)
            elif existing_threat.state == ThreatState.RESOLVED:
                # A previously resolved threat has reappeared!
                self.transition_state(threat.id, ThreatState.UPDATED)
            return

        # New threat, store it
        self.all_threats[threat.id] = threat
        
        if threat.category == ThreatCategory.COMPONENT:
            self.component_threats[threat.id] = threat
        elif threat.category == ThreatCategory.DATA_FLOW:
            self.data_flow_threats[threat.id] = threat
        elif threat.category == ThreatCategory.ATTACK_PATH:
            self.attack_path_threats[threat.id] = threat

    def transition_state(self, threat_id: str, new_state: ThreatState):
        """
        State machine transition logic. Ensures strict lifecycle management.
        """
        threat = self.all_threats.get(threat_id)
        if not threat:
            raise ValueError(f"Threat {threat_id} not found in database.")
            
        # Example validation: Cannot mark a false positive as 'New' again
        if threat.state == ThreatState.FALSE_POSITIVE and new_state == ThreatState.NEW:
            raise ValueError("Cannot transition a False Positive back to New without explicit user override.")
            
        threat.state = new_state
            
    def get_threats_by_state(self, state: ThreatState) -> List[Threat]:
        """Filter threats by lifecycle state."""
        return [t for t in self.all_threats.values() if t.state == state]
        
    def reconcile_incremental_run(self, active_threat_ids: List[str]):
        """
        Called after a CI/CD incremental run. Any threat that previously existed
        but is no longer found in the active run should be marked as RESOLVED.
        """
        for threat_id, threat in self.all_threats.items():
            if threat_id not in active_threat_ids:
                if threat.state not in [ThreatState.RESOLVED, ThreatState.ACCEPTED_RISK, ThreatState.FALSE_POSITIVE]:
                    self.transition_state(threat_id, ThreatState.RESOLVED)
