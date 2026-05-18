from __future__ import annotations
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from threatpilot.core.project_manager import Project
from threatpilot.ai.response_parser import convert_reasoning_to_markdown
from threatpilot.risk.cvss_calculator import get_cvss_severity

logger = logging.getLogger(__name__)

def sanitize_md(text: str | None, preserve_newlines: bool = False) -> str:
    """Escape Markdown special characters. If preserve_newlines is False, collapse to single line."""
    if not text:
        return ""
    
    str_val = str(text).strip()
    if not preserve_newlines:
        str_val = str_val.replace("\n", " ").replace("\r", " ").strip()
    
    escape_chars = r"\\`*_{}[]()#+-.!"
    for char in escape_chars:
        if preserve_newlines and char in "#*>-": continue 
        str_val = str_val.replace(char, f"\\{char}")
    return str_val

def export_to_markdown(project: Project, output_path: str | Path) -> None:
    """Generate a comprehensive Markdown threat model report (L.1)."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [
        f"# ThreatPilot Security Analysis Report: {sanitize_md(project.project_name)}",
        f"*Generated on: {now}*",
        "",
        "## 1. Project Overview",
        f"- **Project Name:** {sanitize_md(project.project_name)}",
        f"- **Created:** {project.created_at}",
        f"- **Industry Context:** {sanitize_md(project.prompt_config.industry_context or 'General')}",
        f"- **Security Posture:** {sanitize_md(project.prompt_config.security_posture)}",
        f"- **Risk Preference:** {sanitize_md(project.prompt_config.risk_preference)}",
        "",
        "## 2. Threat Analysis Methodology",
        "The system was analyzed using the **STRIDE** methodology. "
        "Threats were identified and categorized as Spoofing, Tampering, "
        "Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege.",
        "",
        "## 3. Risk Register Summary",
    ]

    threats = project.threat_register.threats
    if not threats:
        lines.append("_No threats identified in the current register._")
    else:
        accepted_count = sum(1 for t in threats if t.is_accepted_risk)
        lines.append(f"- **Total Identified Threats:** {len(threats)}")
        lines.append(f"- **Accepted Risks:** {accepted_count}")
        lines.append(f"- **Pending Mitigations:** {len(threats) - accepted_count}")
        lines.append("")
        lines.append("## 4. Detailed Findings")
        
        grouped = defaultdict(list)
        for t in threats:
            grouped[t.category.value].append(t)
            
        for category, items in grouped.items():
            lines.append(f"### {category}")
            for t in items:
                status = "✅ [ACCEPTED]" if t.is_accepted_risk else "❌ [ACTIVE]"
                severity = get_cvss_severity(t.cvss_score)
                
                elem_name, asset_name = t.resolve_affected_elements(project)
                affected_str = f"{elem_name} / {asset_name}" if elem_name != asset_name else elem_name
                
                lines.append(f"#### {status} {sanitize_md(t.title)}")
                lines.append(f"- **Risk Level:** {severity} (Score: {t.cvss_score})")
                lines.append(f"- **Likelihood:** {t.likelihood}/5")
                if t.cvss_vector:
                    lines.append(f"- **CVSS Vector:** `{t.cvss_vector}`")
                
                if t.mitre_attack_id:
                    lines.append(f"- **MITRE ATT&CK:** {sanitize_md(t.mitre_attack_id)} ({sanitize_md(t.mitre_attack_technique)})")
                
                if affected_str:
                    lines.append(f"- **Affected Architecture:** {sanitize_md(affected_str)}")
                
                lines.append(f"- **Description:** {sanitize_md(t.description)}")
                v_ids = getattr(t, "vulnerability_ids", [])
                if v_ids and hasattr(project, "vulnerability_register"):
                    v_descs = [getattr(v, "title", "New Vulnerability") for vid in v_ids if (v := project.vulnerability_register.get_vulnerability(vid))]
                    if v_descs:
                        lines.append(f"- **Vulnerabilities:** {sanitize_md('; '.join(v_descs))}")
                lines.append(f"- **Impact:** {sanitize_md(t.impact)}")
                lines.append(f"- **Mitigation Strategy:** {sanitize_md(t.mitigation)}")
                
                if t.is_accepted_risk and t.acceptance_justification:
                    lines.append(f"- **Acceptance Rationale:** {sanitize_md(t.acceptance_justification)}")
                
                if t.reasoning:
                    lines.append("- **XAI Reasoning:**")
                    md_reasoning = convert_reasoning_to_markdown(t.reasoning)
                    reasoning_lines = md_reasoning.splitlines()
                    for r_line in reasoning_lines:
                        if r_line.strip():
                            lines.append(f"  > {r_line.strip()}")
                        else:
                            lines.append("  >")
                
                lines.append("")

    lines.append("---")
    lines.append("*End of Report - Generated by ThreatPilot*")
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
