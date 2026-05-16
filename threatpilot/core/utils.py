"""Core utility functions for architectural model manipulation and resolution."""

from __future__ import annotations
from typing import Any, List, Optional

def find_component_by_name(name: str, components: List[Any]) -> Optional[Any]:
    """Finds a component by name using fuzzy matching."""
    if not name: return None
    s = name.strip().lower()
    for c in components:
        cn = c.name.strip().lower()
        if cn == s or s in cn or cn in s: return c
    return None

def find_flow_by_name(name: str, flows: List[Any]) -> Optional[Any]:
    """Finds a data flow by name using fuzzy matching."""
    if not name: return None
    s = name.strip().lower()
    for f in flows:
        fn = f.name.strip().lower()
        if fn == s or s in fn or fn in s: return f
    return None

def resolve_architecture_elements(
    description_haystack: str,
    component_hint: str,
    components: List[Any],
    flows: List[Any]
) -> tuple[str, str]:
    """Resolves involved element and asset names from a threat description and component hint."""
    haystack = (f"{component_hint} {description_haystack}").lower()
    
    # Check explicitly hinted components/flows first
    for hint in [h.strip() for h in component_hint.split(",") if h.strip()]:
        if flow := find_flow_by_name(hint, flows):
            src = next((c.name for c in components if c.component_id == flow.source_id), "")
            dst = next((c.name for c in components if c.component_id == flow.target_id), "")
            if src or dst: return src, dst
        
        if comp := find_component_by_name(hint, components):
            return comp.name, comp.name

    # Fallback to fuzzy search in haystack
    for f in flows:
        if f.name.lower() in haystack:
            src = next((c.name for c in components if c.component_id == f.source_id), "")
            dst = next((c.name for c in components if c.component_id == f.target_id), "")
            if src or dst: return src, dst

    found = [c.name for c in components if c.name.lower() in haystack]
    if len(found) >= 2: return found[0], found[1]
    if len(found) == 1: return found[0], found[0]
    
    return "", ""
