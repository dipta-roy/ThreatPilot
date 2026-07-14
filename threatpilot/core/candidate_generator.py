from typing import List
from threatpilot.core.dfd_converter import DFDModel
from threatpilot.core.threat_model import STRIDECategory

def generate_candidates(dfd: DFDModel, analysis_mode: str = "STRIDE") -> List[str]:
    """
    Deterministically generates a list of candidate threat categories 
    based on the elements present in the DFD segment.
    """
    candidates = set()
    mode = analysis_mode.upper()
    
    has_nodes = len(dfd.nodes) > 0
    has_edges = len(dfd.edges) > 0
    
    if mode == "STRIDE":
        if has_edges:
            # Data Flows generally subject to Tampering, Info Disclosure, DoS
            candidates.update([
                STRIDECategory.TAMPERING.value,
                STRIDECategory.INFORMATION_DISCLOSURE.value,
                STRIDECategory.DENIAL_OF_SERVICE.value
            ])
            # If it crosses a boundary, add Spoofing
            candidates.add(STRIDECategory.SPOOFING.value)
            
        elif has_nodes:
            # For component segments, check type
            for node in dfd.nodes:
                ntype = (node.type or "").lower()
                if "process" in ntype:
                    candidates.update(STRIDECategory.get_stride_values())
                elif "data store" in ntype:
                    candidates.update([
                        STRIDECategory.TAMPERING.value,
                        STRIDECategory.INFORMATION_DISCLOSURE.value,
                        STRIDECategory.DENIAL_OF_SERVICE.value
                    ])
                elif "external" in ntype:
                    candidates.update([
                        STRIDECategory.SPOOFING.value,
                        STRIDECategory.REPUDIATION.value
                    ])
                else:
                    # Fallback to all
                    candidates.update(STRIDECategory.get_stride_values())
    else:
        # LINDDUN
        candidates.update(STRIDECategory.get_linddun_values())
        
    return sorted(list(candidates))
