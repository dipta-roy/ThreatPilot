"""AI response parsing module for ThreatPilot.

Contains the logic to extract structured JSON data from raw AI responses,
handling various formatting artifacts such as markdown code blocks.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


def extract_json(text: str) -> Optional[Any]:
    """Helper to extract a JSON object from a text string.

    Handles markdown code blocks and attempts to auto-repair truncated 
    JSON by backtracking to the last valid object in a list.

    Args:
        text: The raw response text from the AI.

    Returns:
        The parsed Python object (list or dict), or ``None`` if no JSON
        could be extracted/parsed.
    """
    if not text:
        return None

    # 1. Primary Extraction: Try to find a JSON block via markdown or raw markers
    content = ""
    # Look for markdown block
    code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)(?:```|$)", text)
    if code_block_match:
        content = code_block_match.group(1).strip()
    else:
        # Fallback: Find matching start marker
        first_brace = text.find("{")
        first_bracket = text.find("[")
        start_idx = -1
        if first_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
            start_idx = first_brace
        elif first_bracket != -1:
            start_idx = first_bracket
            
        if start_idx == -1:
            return None
        content = text[start_idx:].strip()

    if not content:
        return None

    # 2. Iterative Recovery: If JSON is truncated, backtrack to find the last valid segment
    # This is much more robust than just adding closing brackets to a broken string.
    
    # 2. Iterative Recovery: If JSON is truncated, backtrack to find the last valid segment
    # Pre-clean: common trailing comma issue
    clean_content = re.sub(r",\s*([\]\}])", r"\1", content)
    
    # 2a. Simple direct attempt first
    try:
        return json.loads(clean_content)
    except json.JSONDecodeError:
        pass

    # 2b. Aggressive Recovery: Delimiter Balancing
    # This handles cases where the AI just stops mid-word/mid-field.
    stack = []
    in_string = False
    escaped = False
    
    # Track brackets, braces, and strings to close them correctly
    for char in clean_content:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            if in_string:
                stack.pop()
                in_string = False
            else:
                stack.append('"')
                in_string = True
            continue
        if not in_string:
            if char == "{":
                stack.append("}")
            elif char == "[":
                stack.append("]")
            elif char == "}":
                if stack and stack[-1] == "}": stack.pop()
            elif char == "]":
                if stack and stack[-1] == "]": stack.pop()

    # Create a repaired version of the content
    repaired = clean_content
    temp_stack = stack[:]
    
    if in_string:
        repaired += '"'
        if temp_stack and temp_stack[-1] == '"': temp_stack.pop()
            
    while temp_stack:
        delim = temp_stack.pop()
        repaired = repaired.strip()
        if repaired.endswith(","):
            repaired = repaired[:-1].strip()
        repaired += delim
        
    try:
         # Clean up any trailing commas that might have been hidden inside the structure
         repaired = re.sub(r",\s*([\]\}])", r"\1", repaired)
         return json.loads(repaired)
    except json.JSONDecodeError:
         pass


    # Recovery Strategy for Lists: find the last complete object '}'
    if content.startswith("["):
        last_brace = content.rfind("}")
        while last_brace != -1:
            candidate = content[:last_brace + 1].strip()
            if candidate.endswith(","):
                candidate = candidate[:-1].strip()
            candidate += "]"
            try:
                candidate = re.sub(r",\s*([\]\}])", r"\1", candidate)
                return json.loads(candidate)
            except json.JSONDecodeError:
                last_brace = content.rfind("}", 0, last_brace)
        
    # Recovery Strategy for Single Objects
    elif content.startswith("{"):
        last_brace = content.rfind("}")
        while last_brace != -1:
            candidate = content[:last_brace + 1].strip()
            if candidate.endswith(","):
                candidate = candidate[:-1].strip()
            candidate += "}"
            try:
                candidate = re.sub(r",\s*([\]\}])", r"\1", candidate)
                return json.loads(candidate)
            except json.JSONDecodeError:
                last_brace = content.rfind("}", 0, last_brace)
                
    return None


def _normalize_impact(val: Any) -> str:
    """Standardize messy AI impact strings into Low, Medium, High, or Critical."""
    if not isinstance(val, str):
        return "Medium"
        
    v = val.lower().strip()
    if "critical" in v: return "Critical"
    if "high" in v: return "High"
    if "medium" in v or "med" in v: return "Medium"
    if "low" in v or "minor" in v: return "Low"
    
    # Fallback for descriptions that don't name a level
    # If it's very long, it's likely a description; default to Medium
    return "Medium"


def parse_threat_list(raw_response: str) -> List[Dict[str, Any]]:
    """Parse a list of threats from the AI's response text.

    Expected format (from PromptBuilder):
        A list of JSON objects with:
        threat_id, category, title, description, impact, likelihood, recommended_mitigation

    Args:
        raw_response: The text generated by the AI provider.

    Returns:
        A list of extracted dictionaries containing threat metadata.
    """
    obj = extract_json(raw_response)
    threats = []
    
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        # Handle cases where AI wraps the list in a key like 'threats'
        for key in ("threats", "analysis", "results"):
            if key in obj and isinstance(obj[key], list):
                return obj[key]
        return [obj]
    
    return []
