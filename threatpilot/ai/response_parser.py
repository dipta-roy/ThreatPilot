"""AI response parsing module for ThreatPilot.

Contains the logic to extract structured JSON data from raw AI responses,
handling various formatting artifacts such as markdown code blocks.
"""

from __future__ import annotations
import ast
import json
import re
from typing import Any, Dict, List, Optional

def extract_json(text: str) -> Optional[Any]:
    """Helper to extract a JSON object from a text string.

    Handles markdown code blocks and attempts to auto-repair truncated 
    JSON by backtracking to the last valid object in a list.
    Supports Python literal fallback (ast) for models using single quotes.

    Args:
        text: The raw response text from the AI.

    Returns:
        The parsed Python object (list or dict), or ``None`` if no JSON
        could be extracted/parsed.
    """
    if not text:
        return None

    content = ""
    code_block_match = re.search(r"```(?:json|python)?\s*([\s\S]*?)(?:```|$)", text, re.IGNORECASE)
    if code_block_match:
        content = code_block_match.group(1).strip()
    else:
        first_brace = text.find("{")
        first_bracket = text.find("[")
        start_idx = -1
        if first_brace != -1 and (first_bracket == -1 or first_brace < first_bracket):
            start_idx = first_brace
        elif first_bracket != -1:
            start_idx = first_bracket
            
        if start_idx == -1:
            return None
        last_brace = text.rfind("}")
        last_bracket = text.rfind("]")
        end_idx = max(last_brace, last_bracket)
        if end_idx == -1:
             content = text[start_idx:].strip()
        else:
             content = text[start_idx:end_idx+1].strip()

    if not content:
        return None
    
    clean_content = re.sub(r",\s*([\]\}])", r"\1", content)
    
    try:
        return json.loads(clean_content)
    except json.JSONDecodeError:
        pass

    try:
        return ast.literal_eval(clean_content)
    except (ValueError, SyntaxError, TypeError):
        pass

    stack = []
    in_string = False
    quote_char = None
    escaped = False
    
    for char in clean_content:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in ('"', "'"):
            if in_string:
                if char == quote_char:
                    stack.pop()
                    in_string = False
                    quote_char = None
            else:
                stack.append(char)
                in_string = True
                quote_char = char
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

    repaired = clean_content
    temp_stack = stack[:]
    
    if in_string:
        repaired += quote_char
        if temp_stack and temp_stack[-1] == quote_char: temp_stack.pop()
            
    while temp_stack:
        delim = temp_stack.pop()
        repaired = repaired.strip()
        if repaired.endswith(","):
            repaired = repaired[:-1].strip()
        repaired += delim
        
    try:
         repaired = re.sub(r",\s*([\]\}])", r"\1", repaired)
         try:
             return json.loads(repaired)
         except json.JSONDecodeError:
             return ast.literal_eval(repaired)
    except Exception:
         pass

    if content.startswith("["):
        last_brace = content.rfind("}")
        while last_brace != -1:
            candidate = content[:last_brace + 1].strip()
            if candidate.endswith(","):
                candidate = candidate[:-1].strip()
            candidate += "]"
            try:
                candidate = re.sub(r",\s*([\]\}])", r"\1", candidate)
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    return ast.literal_eval(candidate)
            except Exception:
                last_brace = content.rfind("}", 0, last_brace)
        
    elif content.startswith("{"):
        last_brace = content.rfind("}")
        while last_brace != -1:
            candidate = content[:last_brace + 1].strip()
            if candidate.endswith(","):
                candidate = candidate[:-1].strip()
            candidate += "}"
            try:
                candidate = re.sub(r",\s*([\]\}])", r"\1", candidate)
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    return ast.literal_eval(candidate)
            except Exception:
                last_brace = content.rfind("}", 0, last_brace)
                
    return None

from threatpilot.core.threat_model import Threat, STRIDECategory

def _normalize_impact(val: Any) -> str:
    """Standardize messy AI impact strings (M.2)."""
    if not isinstance(val, str):
        return "Medium"
    v = val.lower().strip()
    if "critical" in v: return "Critical"
    if "high" in v: return "High"
    if "medium" in v or "med" in v: return "Medium"
    if "low" in v or "minor" in v: return "Low"
    return "Medium"

def map_category(cat_str: str) -> STRIDECategory:
    """Fuzzy map text categories from AI to the standard STRIDE/LINDDUN enum."""
    s = str(cat_str).lower().strip()
    
    for member in STRIDECategory:
        if s == member.value.lower() or s == member.name.lower():
            return member
    if "spoofing" in s: return STRIDECategory.SPOOFING
    if "tampering" in s: return STRIDECategory.TAMPERING
    if "repudiation" in s:
        if "non" in s or "privacy" in s: return STRIDECategory.NON_REPUDIATION_PRIVACY
        return STRIDECategory.REPUDIATION
    if "denial" in s or "dos" in s: return STRIDECategory.DENIAL_OF_SERVICE
    if "privilege" in s or "elevation" in s: return STRIDECategory.ELEVATION_OF_PRIVILEGE
    
    if "linkability" in s: return STRIDECategory.LINKABILITY
    if "identifiability" in s: return STRIDECategory.IDENTIFIABILITY
    if "detectability" in s: return STRIDECategory.DETECTABILITY
    if "unawareness" in s: return STRIDECategory.UNAWARENESS
    if "compliance" in s: return STRIDECategory.NON_COMPLIANCE

    if "disclosure" in s or "information" in s:
        if "privacy" in s or "personal" in s or "pii" in s:
            return STRIDECategory.DISCLOSURE_OF_INFORMATION
        return STRIDECategory.INFORMATION_DISCLOSURE
    
    return STRIDECategory.INFORMATION_DISCLOSURE

def parse_threat_list(raw_response: str) -> List[Dict[str, Any]]:
    """Parse and validate a list of threats from the AI (M.2)."""
    obj = extract_json(raw_response)
    valid_threats = []
    
    candidates = []
    if isinstance(obj, list):
        candidates = obj
    elif isinstance(obj, dict):
        for key in ("threats", "analysis", "results", "findings", "items"):
            if key in obj and isinstance(obj[key], list):
                candidates = obj[key]
                break
        else:
            candidates = [obj]
    
    for item in candidates:
        if not isinstance(item, dict):
            continue
            
        mapping = {
            "threat": "title",
            "name": "title",
            "mitigation": "mitigation",
            "recommended_mitigation": "mitigation",
            "remediation": "mitigation",
            "stride": "category",
            "threat_category": "category",
            "type": "category",
            "mitre_technique_id": "mitre_attack_id",
            "mitre_id": "mitre_attack_id",
            "attack_id": "mitre_attack_id",
            "mitre_technique": "mitre_attack_technique",
            "attack_technique": "mitre_attack_technique",
            "affected_element": "affected_element",
            "affected_item": "affected_element",
            "component": "affected_components",
            "score": "cvss_score",
            "cvss": "cvss_score",
            "vector": "cvss_vector",
            "cvss_31_vector": "cvss_vector"
        }
        for k_ai, k_model in mapping.items():
            if k_ai in item and (k_model not in item or not item[k_model]):
                item[k_model] = item[k_ai]
        
        str_fields = ["title", "description", "mitigation", "vulnerabilities", "affected_components", "impact"]
        for f in str_fields:
            if f in item and isinstance(item[f], list):
                item[f] = ", ".join(str(x) for x in item[f])
            elif f in item:
                item[f] = str(item[f])

        cat_val = item.get("category", "Information Disclosure")
        item["category"] = map_category(str(cat_val))

        item["impact"] = _normalize_impact(item.get("impact", "Medium"))
        
        try:
            val_lh = item.get("likelihood", 3)
            item["likelihood"] = int(float(str(val_lh))) if val_lh is not None else 3
        except (ValueError, TypeError):
            item["likelihood"] = 3
            
        try:
            val_cvss = item.get("cvss_score", 0.0)
            item["cvss_score"] = float(str(val_cvss)) if val_cvss is not None else 0.0
        except (ValueError, TypeError):
            item["cvss_score"] = 0.0

        # Auto-sync score with vector if present
        cvss_v = item.get("cvss_vector", "")
        if cvss_v and str(cvss_v).startswith("CVSS:3.1/"):
            try:
                from threatpilot.risk.cvss_calculator import parse_cvss_vector, calculate_cvss_base_score
                metrics = parse_cvss_vector(str(cvss_v))
                calc_score = calculate_cvss_base_score(metrics)
                item["cvss_score"] = calc_score
            except Exception:
                pass

        if "threat_id" not in item or not str(item["threat_id"]).strip():
             import uuid
             item["threat_id"] = uuid.uuid4().hex
        try:
            Threat.model_validate(item)
            valid_threats.append(item)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(f"VAL-FAILURE: AI threat '{item.get('title', 'Unknown')}' failed validation: {exc}")
            
    return valid_threats

_XAI_SECTION_MAP = {
    "attack_vector":            "### 1. Attack Vector",
    "architectural_root_cause": "### 2. Architectural Root Cause",
    "risk_rationalization":     "### 3. Risk Rationalization",
    "framework_alignment":      "### 4. Framework Alignment",
}

def convert_reasoning_to_markdown(raw: str, markdown: bool = True) -> str:
    """Convert a raw AI reasoning string to display-ready Markdown or Plaintext.

    Handles four possible formats:
    1. Already well-formed Markdown (pass-through).
    2. JSON object string  – parsed via ``json.loads``.
    3. Python dict literal  – parsed via ``ast.literal_eval``.
    4. Mixed-quote dict string – extracted via positional regex.

    Args:
        raw: The raw input string from the AI.
        markdown: If False, strips '###' markers for Excel/plaintext use.
    """
    if not raw or raw == "Reasoning not yet generated.":
        return raw

    text = re.sub(r"^Technical Reasoning\s*[:\-]?\s*\n+", "", raw.strip(), flags=re.IGNORECASE).strip()

    brace_match = re.search(r"\{[\s\S]+\}", text)
    if not brace_match:
        return text

    candidate = brace_match.group(0)
    data: dict | None = None

    try:
        data = json.loads(candidate)
    except Exception:
        pass

    if data is None:
        try:
            data = ast.literal_eval(candidate)
        except Exception:
            pass

    if data is None:
        key_pat = re.compile(r"[\"\']([\w]+)[\"\']\s*:\s*", re.DOTALL)
        matches = list(key_pat.finditer(candidate))
        if matches:
            result: dict = {}
            for i, m in enumerate(matches):
                key = m.group(1)
                v_start = m.end()
                v_end = matches[i + 1].start() if i + 1 < len(matches) else len(candidate)
                raw_val = candidate[v_start:v_end].strip().rstrip(",").strip()
                if len(raw_val) >= 2 and raw_val[0] in ('"', "'"):
                    q = raw_val[0]
                    end_q = raw_val.rfind(q)
                    raw_val = raw_val[1:end_q] if end_q > 0 else raw_val[1:]
                result[key] = raw_val
            if result:
                data = result

    if not isinstance(data, dict):
        return text

    res = ""
    for key, heading in _XAI_SECTION_MAP.items():
        if key in data:
            val = data[key]
            if not val: continue
            
            if isinstance(val, dict):
                val = "\n".join(f"- {k}: {v}" for k, v in val.items())
            elif isinstance(val, list):
                val = "\n".join(f"- {item}" for item in val)
            
            h = heading if markdown else heading.replace("### ", "").strip()
            res += f"{h}\n\n{val}\n\n"
            
    for key, val in data.items():
        if key not in _XAI_SECTION_MAP:
            h = key.replace('_', ' ').title()
            if markdown: h = f"### {h}"
            res += f"{h}\n\n{val}\n\n"
            
    return res.strip()
