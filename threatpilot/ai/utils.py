"""AI utility module for ThreatPilot.

Provides helper functions for fuzzy matching AI-generated text to architectural 
elements and standardizing data formats.
"""

from __future__ import annotations
from typing import Any, List, Optional

from threatpilot.core.utils import find_component_by_name, find_flow_by_name, resolve_architecture_elements

def fuzzy_find_component(name: str, components: List[Any]) -> Optional[Any]:
    """Finds a component in the list using fuzzy name matching."""
    return find_component_by_name(name, components)

def fuzzy_find_flow(name: str, flows: List[Any]) -> Optional[Any]:
    """Finds a data flow in the list using fuzzy name matching."""
    return find_flow_by_name(name, flows)

def resolve_element_names(haystack: str, components: List[Any], flows: List[Any]) -> tuple[str, str]:
    """Resolves source and target element names from a descriptive text block."""
    return resolve_architecture_elements(haystack, "", components, flows)
