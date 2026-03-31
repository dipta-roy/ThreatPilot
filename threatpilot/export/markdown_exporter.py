"""Markdown report exporter module for ThreatPilot.

Generates a structured, human-readable security analysis report in Markdown
format based on the current project metadata and threat register.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from threatpilot.core.project_manager import Project
from threatpilot.ai.response_parser import convert_reasoning_to_markdown


def sanitize_md(text: str | None, preserve_newlines: bool = False) -> str:
    """Escape Markdown special characters. If preserve_newlines is False, collapse to single line."""
    if not text:
        return ""
    
    str_val = str(text).strip()
    if not preserve_newlines:
        str_val = str_val.replace("\n", " ").replace("\r", " ").strip()
    
    # Escape characters that have structural meaning in Markdown
    # We escape broadly to prevent raw input from breaking report layout
    # but for reasoning/description we should be more careful.
    escape_chars = r"\\`*_{}[]()#+-.!"
    for char in escape_chars:
        # Don't escape # or * if we're in a multi-line "long text" block (preserving some MD)
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

    # Summarise counts
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
        
        # Group by category for cleaner output
        from collections import defaultdict
        grouped = defaultdict(list)
        for t in threats:
            grouped[t.category.value].append(t)
            
        for category, items in grouped.items():
            lines.append(f"### {category}")
            for t in items:
                status = "✅ [ACCEPTED]" if t.is_accepted_risk else "❌ [ACTIVE]"
                
                # Derive severity from CVSS score
                from threatpilot.risk.cvss_calculator import get_cvss_severity
                severity = get_cvss_severity(t.cvss_score)
                
                # Extract component-level classifications
                comp_details = []
                if t.affected_components:
                    names = [n.strip() for n in t.affected_components.split(",")]
                    for name in names:
                        for c in project.components:
                            if c.name == name:
                                # Sanitize names that might contain MD injection
                                s_name = sanitize_md(c.name)
                                s_el = sanitize_md(c.element_classification)
                                s_as = sanitize_md(c.asset_classification)
                                comp_details.append(f"{s_name} ({s_el} / {s_as})")
                                break
                
                lines.append(f"#### {status} {sanitize_md(t.title)}")
                lines.append(f"- **Risk Level:** {severity} (Score: {t.cvss_score})")
                lines.append(f"- **Likelihood:** {t.likelihood}/5")
                if t.cvss_vector:
                    lines.append(f"- **CVSS Vector:** `{t.cvss_vector}`")
                
                if t.mitre_attack_id:
                    lines.append(f"- **MITRE ATT&CK:** {sanitize_md(t.mitre_attack_id)} ({sanitize_md(t.mitre_attack_technique)})")
                
                if comp_details:
                    lines.append(f"- **Affected Assets:** {', '.join(comp_details)}")
                elif t.affected_components:
                    lines.append(f"- **Affected Components:** {sanitize_md(t.affected_components)}")
                
                lines.append(f"- **Description:** {sanitize_md(t.description)}")
                if t.vulnerabilities:
                    lines.append(f"- **Vulnerabilities:** {sanitize_md(t.vulnerabilities)}")
                lines.append(f"- **Impact:** {sanitize_md(t.impact)}")
                lines.append(f"- **Mitigation Strategy:** {sanitize_md(t.mitigation)}")
                
                if t.is_accepted_risk and t.acceptance_justification:
                    lines.append(f"- **Acceptance Rationale:** {sanitize_md(t.acceptance_justification)}")
                
                if t.reasoning:
                    lines.append("- **XAI Reasoning:**")
                    # Convert raw JSON/Dict to Markdown paragraphs using the shared utility
                    md_reasoning = convert_reasoning_to_markdown(t.reasoning)
                    
                    # Indent and prepend '>' for blockquote look
                    reasoning_lines = md_reasoning.splitlines()
                    for r_line in reasoning_lines:
                        if r_line.strip():
                            lines.append(f"  > {r_line.strip()}")
                        else:
                            lines.append("  >")
                
                lines.append("")

    lines.append("---")
    lines.append("*End of Report - Generated by ThreatPilot*")

    # Write to file
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
