"""AI response parsing module for ThreatPilot.

Contains the logic to extract structured JSON data from raw AI responses,
handling various formatting artifacts such as markdown code blocks.
"""

from __future__ import annotations
import ast
import json
import re
from typing import Any, Dict, List, Optional
from threatpilot.core.domain_models import Component, Flow, TrustBoundary, ElementType, AssetType
from threatpilot.core.threat_model import Threat, STRIDECategory, Vulnerability
from threatpilot.core.constants import AI_FIELD_MAPPING, AI_VULN_KEYS
from threatpilot.ai.utils import fuzzy_find_component, fuzzy_find_flow, resolve_element_names

def map_element_type(et_str: str) -> ElementType:
    """Fuzzy maps AI-generated text to standard DFD ElementType enums."""
    s = str(et_str).lower().strip()
    if any(x in s for x in ["process", "service", "web", "app", "worker", "function"]): return ElementType.PROCESS
    if any(x in s for x in ["store", "database", "db", "bucket", "file", "disk", "cloud"]): return ElementType.DATA_STORE
    if any(x in s for x in ["entity", "user", "actor", "person", "client", "external"]): return ElementType.ENTITY
    if any(x in s for x in ["flow", "dataflow", "arrow"]): return ElementType.DATA_FLOW
    
    # Check exact matches
    for e in ElementType:
        if s == e.value.lower() or s == e.name.lower(): return e
    return ElementType.PROCESS

def extract_json(text: str) -> Optional[Any]:
    """Extracts and repairs JSON or Python literal objects from raw text strings."""
    if not text: return None
    if (m := re.search(r"```(?:json|python)?\s*([\s\S]*?)(?:```|$)", text, re.IGNORECASE)): content = m.group(1).strip()
    else:
        fb, fk = text.find("{"), text.find("[")
        start = fb if fb != -1 and (fk == -1 or fb < fk) else fk
        if start == -1: return None
        end = max(text.rfind("}"), text.rfind("]"))
        content = text[start:end+1].strip() if end != -1 else text[start:].strip()

    if not content: return None
    clean = re.sub(r",\s*([\]\}])", r"\1", content)
    for method in [json.loads, ast.literal_eval]:
        try: return method(clean)
        except Exception: continue

    # Advanced repair loop
    stack = []; in_str = False; q_char = None; escaped = False
    for char in clean:
        if escaped: escaped = False; continue
        if char == "\\": escaped = True; continue
        if char in ('"', "'"):
            if in_str:
                if char == q_char: stack.pop(); in_str = False; q_char = None
            else: stack.append(char); in_str = True; q_char = char
        elif not in_str:
            if char == "{": stack.append("}")
            elif char == "[": stack.append("]")
            elif char in ("}", "]") and stack and stack[-1] == char: stack.pop()

    rep = clean; t_stack = stack[:]
    if in_str: rep += q_char; t_stack.pop() if t_stack and t_stack[-1] == q_char else None
    while t_stack:
        delim = t_stack.pop(); rep = rep.strip()
        if rep.endswith(","): rep = rep[:-1].strip()
        rep += delim
        
    for method in [json.loads, ast.literal_eval]:
        try: return method(re.sub(r",\s*([\]\}])", r"\1", rep))
        except Exception: continue

    # Truncated JSON recovery
    for marker, wrapper in [("[", "]"), ("{", "}")]:
        if content.startswith(marker):
            lb = content.rfind("}")
            while lb != -1:
                cand = re.sub(r",\s*([\]\}])", r"\1", (content[:lb + 1].strip().rstrip(",") + wrapper))
                try: return json.loads(cand)
                except Exception:
                    try: return ast.literal_eval(cand)
                    except Exception: lb = content.rfind("}", 0, lb)
    return None

def _normalize_impact(val: Any) -> str:
    """Standardizes non-uniform impact strings into recognized severity levels."""
    if not isinstance(val, str): return "Medium"
    v = val.lower()
    return "Critical" if "crit" in v else "High" if "high" in v else "Low" if any(x in v for x in ["low", "minor"]) else "Medium"

def map_category(cat_str: str, mode: str = "STRIDE") -> STRIDECategory:
    """Performs fuzzy mapping of AI-generated text to standardized threat categories."""
    s = str(cat_str).lower().strip()
    for m in STRIDECategory:
        if s == m.value.lower() or s == m.name.lower(): return m
    
    mapping = {
        "spoofing": STRIDECategory.SPOOFING, "tampering": STRIDECategory.TAMPERING,
        "denial": STRIDECategory.DENIAL_OF_SERVICE, "dos": STRIDECategory.DENIAL_OF_SERVICE,
        "privilege": STRIDECategory.ELEVATION_OF_PRIVILEGE, "elevation": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "linkability": STRIDECategory.LINKABILITY, "identifiability": STRIDECategory.IDENTIFIABILITY,
        "detectability": STRIDECategory.DETECTABILITY, "unawareness": STRIDECategory.UNAWARENESS,
        "compliance": STRIDECategory.NON_COMPLIANCE
    }
    for k, v in mapping.items():
        if k in s: return v
    if "repudiation" in s: return STRIDECategory.NON_REPUDIATION_PRIVACY if any(x in s for x in ["non", "privacy"]) else STRIDECategory.REPUDIATION
    if any(x in s for x in ["disclosure", "information"]):
        return STRIDECategory.DISCLOSURE_OF_INFORMATION if any(x in s for x in ["privacy", "personal", "pii"]) or mode.upper() == "LINDDUN" else STRIDECategory.INFORMATION_DISCLOSURE
    
    # Final default based on mode
    if mode.upper() == "LINDDUN":
        return STRIDECategory.DISCLOSURE_OF_INFORMATION
    return STRIDECategory.INFORMATION_DISCLOSURE

def parse_threat_list(raw_response: str, components: List[Any] = [], flows: List[Any] = [], mode: str = "STRIDE") -> List[Threat]:
    """Validates, sanitizes, and maps threats extracted from an AI response."""
    obj = extract_json(raw_response); candidates = []
    if isinstance(obj, list): candidates = obj
    elif isinstance(obj, dict):
        for k in ("threats", "analysis", "results", "findings", "items"):
            if k in obj and isinstance(obj[k], list): candidates = obj[k]; break
        else: candidates = [obj]
    
    valid_threats = []
    for item in candidates:
        if not isinstance(item, dict): continue
        for ka, km in AI_FIELD_MAPPING.items():
            if ka in item and (km not in item or not item[km]): item[km] = item[ka]
        
        for f in ["title", "description", "mitigation", "affected_components", "impact", "affected_element_type", "affected_asset_type"]:
            if f in item: item[f] = ", ".join(str(x) for x in item[f]) if isinstance(item[f], list) else str(item[f])
        
        rv = []
        for vk in AI_VULN_KEYS:
            if (val := item.get(vk)): rv.extend(val) if isinstance(val, list) else rv.append(val)
        item["vulnerabilities"] = [Vulnerability.model_validate(v) if isinstance(v, dict) else Vulnerability(description=str(v), mitigation=item.get("mitigation", "")) for v in (rv or [item.get("description", "Potential vulnerability.")])]
        item["vulnerability_ids"] = [v.vulnerability_id for v in item["vulnerabilities"]]

        item["category"] = map_category(str(item.get("category", "Information Disclosure")), mode=mode)
        item["impact"] = _normalize_impact(item.get("impact", "Medium"))

        # Programmatic safeguard for descriptive titles
        title = str(item.get("title", "")).strip()
        cat_name = str(item.get("category", "")).strip()
        if title.lower() == cat_name.lower():
            comps = item.get("affected_components", [])
            target = comps[0] if isinstance(comps, list) and comps else "System Element"
            item["title"] = f"{cat_name} on {target}"
        for k, t, d in [("likelihood", int, 3), ("cvss_score", float, 0.0)]:
            raw_val = str(item.get(k, d))
            # Try extracting just the first number (float or int) from strings like "7.5 (High)"
            if (num_match := re.search(r"(\d+(?:\.\d+)?)", raw_val)):
                try: item[k] = t(float(num_match.group(1)))
                except Exception: item[k] = d
            else:
                item[k] = d

        if (cv := item.get("cvss_vector")):
            try:
                from threatpilot.risk.cvss_calculator import parse_cvss_vector, calculate_cvss_base_score
                metrics = parse_cvss_vector(str(cv))
                # Only recalculate if we actually found some metrics in the vector
                if any(getattr(metrics, attr) != "None" for attr in ["confidentiality", "integrity", "availability"]):
                    item["cvss_score"] = calculate_cvss_base_score(metrics)
            except Exception: pass

        if not str(item.get("threat_id", "")).strip():
             import uuid; item["threat_id"] = uuid.uuid4().hex
        
        # Resolve architectural mapping
        if components and (ac := item.get("affected_components")):
            haystack = f"{ac} {item.get('title', '')} {item.get('description', '')}"
            if (f_match := fuzzy_find_flow(ac, flows)):
                src = fuzzy_find_component("", [c for c in components if c.component_id == f_match.source_id])
                dst = fuzzy_find_component("", [c for c in components if c.component_id == f_match.target_id])
                item["affected_element_type"] = src.name if src else ""
                item["affected_asset_type"] = dst.name if dst else ""
            elif (c_match := fuzzy_find_component(ac, components)):
                item["affected_element_type"] = item["affected_asset_type"] = c_match.name
            else:
                el, ass = resolve_element_names(haystack, components, flows)
                if el: item["affected_element_type"], item["affected_asset_type"] = el, ass

        try: valid_threats.append(Threat.model_validate(item))
        except Exception: continue
    return valid_threats

_XAI_SECTION_MAP = {
    "attack_path": "### 1. Attack Path",
    "attack_vector": "### 1. Attack Path", 
    "privacy_impact_path": "### 1. Privacy Impact Path",
    "architectural_root_cause": "### 2. Architectural Root Cause", 
    "risk_rationalization": "### 3. Risk Rationalization", 
    "framework_alignment": "### 4. Framework Alignment"
}

def convert_reasoning_to_markdown(raw: str, markdown: bool = True) -> str:
    """Transforms raw technical reasoning into a formatted Markdown document."""
    if not raw or raw == "Reasoning not yet generated.": return raw
    
    # If it's already structured as a report (e.g. starts with ###), don't re-convert
    if raw.strip().startswith("###"):
        return raw.strip()

    text = re.sub(r"^Technical Reasoning\s*[:\-]?\s*\n+", "", raw.strip(), flags=re.IGNORECASE).strip()
    
    # Only try parsing as JSON if it looks like a JSON object
    if not (text.startswith("{") and text.endswith("}")):
        # If it's not a single JSON block, try finding one inside
        if not (bm := re.search(r"\{[\s\S]*\}", text)): 
            return text
        cand = bm.group(0)
    else:
        cand = text
    
    data = None
    try: 
        data = json.loads(cand)
    except Exception:
        try: data = ast.literal_eval(cand)
        except Exception:
            if (ms := list(re.compile(r"[\"\']([\w]+)[\"\']\s*:\s*", re.DOTALL).finditer(cand))):
                res = {}
                for i, m in enumerate(ms):
                    k = m.group(1); vs, ve = m.end(), ms[i+1].start() if i+1 < len(ms) else len(cand)
                    rv = cand[vs:ve].strip().rstrip(",").strip().rstrip("}").strip()
                    if len(rv) >= 2 and rv[0] in ('"', "'"):
                        q = rv[0]; eq = rv.rfind(q); rv = rv[1:eq] if eq > 0 else rv[1:]
                    res[k] = rv
                data = res

    if not isinstance(data, dict): 
        return text
    
    res = ""
    for k, h in _XAI_SECTION_MAP.items():
        if k in data:
            v = data[k]
            if not v: continue
            if isinstance(v, dict): v = "\n".join(f"- {nk}: {nv}" for nk, nv in v.items())
            elif isinstance(v, list): v = "\n".join(f"- {it}" for it in v)
            res += f"{h if markdown else h.replace('### ', '').strip()}\n\n{v}\n\n"
    
    # Add any fields not in the section map
    for k, v in data.items():
        if k not in _XAI_SECTION_MAP:
            header = k.replace('_', ' ').title()
            res += f"{'### ' if markdown else ''}{header}\n\n{v}\n\n"
    
    return res.strip()


def _clean_key_name(key: str) -> str:
    """Cleans camelCase, underscores, and common run-together security keys into spaced Title Case."""
    # Split underscores
    s = key.replace('_', ' ')
    # Split camelCase
    s = re.sub(r'([a-z])([A-Z])', r'\1 \2', s)
    
    # Map common run-together lowercase strings to spaced words
    s_lower = s.lower().replace(' ', '')
    word_map = {
        "technicalreasoning": "Technical Reasoning",
        "threatcontext": "Threat Context",
        "architecturalrationale": "Architectural Rationale",
        "mitigationeffectiveness": "Mitigation Effectiveness",
        "verificationplan": "Verification Plan",
        "stepbystepprocedure": "Step By Step Procedure",
        "verificationcriteria": "Verification Criteria",
        "expectedoutcome": "Expected Outcome",
        "logverification": "Log Verification",
        "negativetest": "Negative Test",
        "coreprinciples": "Core Principles",
        "securitythreatmitigation": "Security Threat Mitigation",
        "securityimpact": "Security Impact",
        "expectedresult": "Expected Result",
        "reqid": "Req-Id",
        "requirementid": "Requirement-Id",
        "affectedcomponents": "Affected Components"
    }
    
    if s_lower in word_map:
        return word_map[s_lower]
    return s.title()


def _split_run_together_steps(text: str) -> list[str]:
    """Splits run-together numbered items (e.g. '1. Step 1: ... 2. Step 2: ...') into list elements."""
    parts = re.split(r'\s+(?=\d+\.\s+(?:Step\s+\d+|[A-Z]))', text)
    if len(parts) > 1:
        return [p.strip() for p in parts if p.strip()]
    return [text]


def _format_value_to_markdown(val: Any, indent_level: int = 0) -> str:
    """Helper to recursively format nested dictionaries and lists into clean Markdown."""
    indent = "  " * indent_level
    if isinstance(val, dict):
        lines = []
        for k, v in val.items():
            section_title = _clean_key_name(k)
            if indent_level == 0:
                lines.append(f"**{section_title}**:")
                lines.append(_format_value_to_markdown(v, indent_level + 1))
                lines.append("")
            else:
                lines.append(f"{indent}- **{section_title}**:")
                lines.append(_format_value_to_markdown(v, indent_level + 1))
        return "\n".join(lines).strip()
    elif isinstance(val, list):
        lines = []
        for index, item in enumerate(val):
            if isinstance(item, dict):
                item_lines = []
                step_val = item.get("step") or item.get("step_number") or (index + 1)
                action_val = item.get("action") or item.get("description") or ""
                
                item_lines.append(f"{indent}{index + 1}. **Step {step_val}**: {action_val}")
                for sk, sv in item.items():
                    if sk in ["step", "action", "description", "step_number"]:
                        continue
                    sk_title = _clean_key_name(sk)
                    item_lines.append(f"{indent}   - **{sk_title}**: {sv}")
                lines.append("\n".join(item_lines))
            elif isinstance(item, str):
                parts = _split_run_together_steps(item)
                for part in parts:
                    lines.append(f"{indent}- {part}")
            else:
                lines.append(f"{indent}- {item}")
        return "\n".join(lines).strip()
    else:
        str_val = str(val)
        parts = _split_run_together_steps(str_val)
        if len(parts) > 1:
            return "\n".join(f"{indent}- {p}" for p in parts)
        if indent_level > 0 and "\n" in str_val:
            return "\n".join(f"{indent}{line}" for line in str_val.splitlines())
        return f"{indent}{str_val}"


def _format_unstructured_text(raw: str) -> str:
    """Parses raw unstructured text line-by-line to construct a beautifully formatted Markdown report."""
    lines = [line.strip() for line in raw.splitlines()]
    
    # 1. First pass: find metadata (Req-Id and Title) to construct the main header
    req_id = ""
    title = ""
    for line in lines:
        line_clean = re.sub(r'^[#\s\-\*]+', '', line).strip()
        if re.match(r'^(?:req[-_]?id|requirement[-_]?id)\s*:\s*(.*)', line_clean, re.IGNORECASE):
            req_id = re.match(r'^(?:req[-_]?id|requirement[-_]?id)\s*:\s*(.*)', line_clean, re.IGNORECASE).group(1).strip()
        elif re.match(r'^title\s*:\s*(.*)', line_clean, re.IGNORECASE):
            title = re.match(r'^title\s*:\s*(.*)', line_clean, re.IGNORECASE).group(1).strip()
            
    # Normalize headers mapping
    header_mapping = {
        "technical reasoning": "### Technical Reasoning",
        "deep technical reasoning": "### Technical Reasoning",
        "verification plan": "### Verification Plan",
        "security threats": "#### Security Threats",
        "threats": "#### Security Threats",
        "rationale": "#### Rationale",
        "architectural rationale": "#### Architectural Rationale",
        "implementation architecture": "#### Implementation Architecture",
        "tools": "#### Tools",
        "test procedures": "#### Test Procedures",
        "test steps": "#### Test Procedures",
        "procedures": "#### Test Procedures",
        "step-by-step procedures": "#### Test Procedures",
        "verification criteria": "#### Verification Criteria",
        "criteria": "#### Verification Criteria",
    }
    
    formatted_lines = []
    
    # Main header at the top
    main_header = "XAI Reasoning & Verification Plan"
    if req_id or title:
        main_header += f" - {req_id} {title}".strip()
    formatted_lines.append(f"### {main_header}")
    formatted_lines.append("")
    
    current_section = ""
    
    # We will process line by line
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line:
            formatted_lines.append("")
            i += 1
            continue
            
        # Strip leading markdown symbols for classification/matching
        line_stripped = re.sub(r'^[#\s\-\*]+', '', line).strip()
        line_lower = line_stripped.lower().rstrip(":")
        
        # If this is the main header repeat, skip it
        if "xai reasoning" in line_lower and "verification plan" in line_lower:
            i += 1
            continue
            
        # Skip raw Requirement/Req-Id/Title lines since they are in the header
        if line_lower in ["requirement", "requirements"]:
            i += 1
            continue
        if re.match(r'^(?:req[-_]?id|requirement[-_]?id)\s*:\s*', line_stripped, re.IGNORECASE):
            i += 1
            continue
        if re.match(r'^title\s*:\s*', line_stripped, re.IGNORECASE):
            i += 1
            continue
            
        # Check if line matches a known header
        matched_header = False
        for hk, hv in header_mapping.items():
            if line_lower == hk or line_lower.startswith(hk + ":") or line_lower.startswith(hk + " :"):
                header_content = ""
                if ":" in line_stripped and line_stripped.lower().startswith(hk):
                    header_content = line_stripped.split(":", 1)[1].strip()
                
                formatted_lines.append(hv)
                formatted_lines.append("")
                current_section = hk
                if header_content:
                    lines[i] = header_content
                    matched_header = True
                    break
                else:
                    i += 1
                    matched_header = True
                    break
        if matched_header:
            continue
            
        # Check if it starts with key: value (like "Logs: Verify...", "Configuration: Ensure...")
        if ":" in line and not line.startswith("-") and not line.startswith("*") and not re.match(r'^\d+\.', line) and not line.startswith("http"):
            parts = line.split(":", 1)
            key_cand = parts[0].strip()
            val_cand = parts[1].strip()
            # If the key is short, format it as bold
            if len(key_cand) < 30 and not any(c in key_cand for c in ["/", "\\", "<", ">", "="]):
                key_clean = _clean_key_name(key_cand)
                val_parts = _split_run_together_steps(val_cand)
                if len(val_parts) > 1:
                    formatted_lines.append(f"**{key_clean}**:")
                    for vp in val_parts:
                        formatted_lines.append(f"  - {vp}")
                else:
                    formatted_lines.append(f"**{key_clean}**: {val_cand}")
                i += 1
                continue
                
        # Default behavior: format based on current section
        list_sections = ["security threats", "threats", "tools"]
        starts_with_list_marker = line.startswith("-") or line.startswith("*") or line.startswith("+") or re.match(r'^\d+\.', line)
        
        if current_section in list_sections and not starts_with_list_marker:
            formatted_lines.append(f"- {line}")
        else:
            parts = _split_run_together_steps(line)
            if len(parts) > 1:
                for part in parts:
                    part_clean = part.strip()
                    if part_clean:
                        if not (part_clean.startswith("-") or part_clean.startswith("*") or re.match(r'^\d+\.', part_clean)):
                            if re.match(r'^Step\s+\d+', part_clean, re.IGNORECASE):
                                formatted_lines.append(part_clean)
                            else:
                                formatted_lines.append(f"- {part_clean}")
                        else:
                            formatted_lines.append(part_clean)
            else:
                formatted_lines.append(line)
                
        i += 1
        
    result = []
    prev_empty = False
    for line in formatted_lines:
        if not line:
            if not prev_empty:
                result.append(line)
                prev_empty = True
        else:
            result.append(line)
            prev_empty = False
            
    return "\n".join(result).strip()


def convert_mitigation_reasoning_to_markdown(raw: str) -> str:
    """Transforms raw mitigation reasoning JSON or text into a formatted Markdown report."""
    if not raw or not raw.strip():
        return ""
    
    # Try to extract the JSON block
    data = extract_json(raw)
    if data and isinstance(data, dict):
        md = []
        
        # Title
        title = data.get("title", "")
        req_id = data.get("requirement_id", data.get("req_id", ""))
        header_text = "XAI Reasoning & Verification Plan"
        if req_id or title:
            header_text += f" - {req_id} {title}".strip()
        md.append(f"### {header_text}")
        md.append("")

        # Dynamically format all fields
        for k, v in data.items():
            if k in ["requirement_id", "req_id", "title"]:
                continue
                
            header = _clean_key_name(k)
            md.append(f"### {header}")
            md.append("")
            md.append(_format_value_to_markdown(v, 0))
            md.append("")

        res = "\n".join(md).strip()
    else:
        res = _format_unstructured_text(raw)

    # Decode any existing HTML entities first, then escape using backslashes for Qt Markdown parser
    res = res.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;lt;", "<").replace("&amp;gt;", ">")
    res = res.replace("<", "\\<").replace(">", "\\>")
    return res

