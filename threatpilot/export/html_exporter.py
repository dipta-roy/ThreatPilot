"""HTML Threat Model Exporter for ThreatPilot.

Generates a gorgeous, self-contained, fully responsive HTML report for security audits.
Includes light/dark mode toggling, interactive collapsible sections, and color-coded severity badges.
"""

from __future__ import annotations
import html
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Any

from threatpilot.core.project_manager import Project
from threatpilot.ai.response_parser import convert_reasoning_to_markdown
from threatpilot.risk.cvss_calculator import get_cvss_severity

def _markdown_to_html(md_text: str) -> str:
    """A lightweight, zero-dependency Markdown-to-HTML converter for AI reasoning."""
    if not md_text:
        return ""
    
    # Escape raw HTML characters to prevent XSS/rendering issues
    escaped = html.escape(md_text)
    
    # Convert headers (### to h4, ## to h3, # to h2)
    escaped = re.sub(r'^###\s+(.*?)$', r'<h5>\1</h5>', escaped, flags=re.MULTILINE)
    escaped = re.sub(r'^##\s+(.*?)$', r'<h4>\1</h4>', escaped, flags=re.MULTILINE)
    escaped = re.sub(r'^#\s+(.*?)$', r'<h3>\1</h3>', escaped, flags=re.MULTILINE)
    
    # Convert bold (**text**)
    escaped = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', escaped)
    
    # Convert italic (*text*)
    escaped = re.sub(r'\*(.*?)\*', r'<em>\1</em>', escaped)
    
    # Convert inline code (`code`)
    escaped = re.sub(r'`(.*?)`', r'<code>\1</code>', escaped)

    # Process lists line-by-line
    lines = escaped.splitlines()
    in_list = False
    formatted_lines = []
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- "):
            if not in_list:
                formatted_lines.append('<ul class="reasoning-list">')
                in_list = True
            formatted_lines.append(f'<li>{stripped[2:]}</li>')
        elif stripped.startswith("* "):
            if not in_list:
                formatted_lines.append('<ul class="reasoning-list">')
                in_list = True
            formatted_lines.append(f'<li>{stripped[2:]}</li>')
        else:
            if in_list:
                formatted_lines.append('</ul>')
                in_list = False
            formatted_lines.append(line)
            
    if in_list:
        formatted_lines.append('</ul>')
        
    # Reassemble and convert remaining newlines to breaks
    final_html = "\n".join(formatted_lines)
    # Protect block-level tags from doubling breaks
    final_html = re.sub(r'(</h5>|</h4>|</h3>|</ul>|</li>)\n', r'\1', final_html)
    final_html = final_html.replace("\n", "<br>")
    return final_html

def export_to_html(project: Project, output_path: str | Path) -> None:
    """Generate a comprehensive and beautiful HTML threat model report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threats = project.threat_register.threats
    
    # Metrics
    total_threats = len(threats)
    accepted_risks = sum(1 for t in threats if t.is_accepted_risk)
    pending_mitigations = total_threats - accepted_risks
    
    # Severity segmentation
    severity_counts = defaultdict(int)
    for t in threats:
        severity_counts[get_cvss_severity(t.cvss_score)] += 1
    
    critical_high_count = severity_counts["Critical"] + severity_counts["High"]

    # Template setup
    html_title = html.escape(f"Threat Model Report: {project.project_name}")
    
    # CSS Stylesheet (sleek, futuristic UI)
    css_styles = """
    :root {
        --bg-primary: #0f172a;
        --bg-secondary: #1e293b;
        --border-color: #334155;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --accent: #38bdf8;
        --accent-hover: #0ea5e9;
        
        --color-critical: #ef4444;
        --color-high: #f97316;
        --color-medium: #eab308;
        --color-low: #22c55e;
        --color-info: #3b82f6;
        
        --color-accepted: #10b981;
        --color-active: #ef4444;
    }
    
    [data-theme="light"] {
        --bg-primary: #f8fafc;
        --bg-secondary: #ffffff;
        --border-color: #e2e8f0;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --accent: #0284c7;
        --accent-hover: #0369a1;
        
        --color-critical: #dc2626;
        --color-high: #ea580c;
        --color-medium: #ca8a04;
        --color-low: #16a34a;
        --color-info: #2563eb;
    }
    
    body {
        margin: 0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        transition: background-color 0.3s, color 0.3s;
    }
    
    header {
        background-color: var(--bg-secondary);
        border-bottom: 1px solid var(--border-color);
        padding: 24px 40px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        position: sticky;
        top: 0;
        z-index: 100;
    }
    
    .logo-area h1 {
        margin: 0;
        font-size: 24px;
        font-weight: 800;
        background: linear-gradient(135deg, var(--accent), #6366f1);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .meta-time {
        font-size: 13px;
        color: var(--text-secondary);
    }
    
    .theme-toggle-btn {
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        color: var(--text-primary);
        padding: 8px 16px;
        border-radius: 20px;
        cursor: pointer;
        font-size: 13px;
        font-weight: bold;
        transition: all 0.2s;
    }
    
    .theme-toggle-btn:hover {
        border-color: var(--accent);
        color: var(--accent);
    }
    
    .main-container {
        max-width: 1200px;
        margin: 40px auto;
        padding: 0 20px;
    }
    
    .project-grid {
        display: grid;
        grid-template-columns: 2fr 1fr;
        gap: 30px;
        margin-bottom: 40px;
    }
    
    @media (max-width: 900px) {
        .project-grid {
            grid-template-columns: 1fr;
        }
    }
    
    .card {
        background-color: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 30px;
        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
    }
    
    .card-title {
        margin-top: 0;
        margin-bottom: 20px;
        font-size: 18px;
        font-weight: 700;
        border-bottom: 2px solid var(--border-color);
        padding-bottom: 10px;
        color: var(--accent);
    }
    
    .meta-list {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    
    .meta-list li {
        display: flex;
        justify-content: space-between;
        padding: 10px 0;
        border-bottom: 1px solid var(--border-color);
    }
    
    .meta-list li:last-child {
        border-bottom: none;
    }
    
    .meta-label {
        font-weight: 600;
        color: var(--text-secondary);
    }
    
    .meta-value {
        font-weight: bold;
    }
    
    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 20px;
        margin-bottom: 40px;
    }
    
    .metric-card {
        background-color: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        position: relative;
        overflow: hidden;
    }
    
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 4px;
        background: linear-gradient(95deg, var(--accent), #6366f1);
    }
    
    .metric-card.critical::before {
        background: var(--color-critical);
    }
    
    .metric-card.accepted::before {
        background: var(--color-accepted);
    }
    
    .metric-num {
        font-size: 36px;
        font-weight: 800;
        margin: 10px 0;
    }
    
    .metric-lbl {
        font-size: 13px;
        color: var(--text-secondary);
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .section-title {
        font-size: 22px;
        font-weight: 800;
        margin-top: 50px;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .section-title::after {
        content: '';
        flex-grow: 1;
        height: 1px;
        background-color: var(--border-color);
    }
    
    .category-group {
        margin-bottom: 30px;
    }
    
    .category-header {
        background-color: var(--bg-secondary);
        border: 1px solid var(--border-color);
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 16px;
        color: var(--accent);
        margin-bottom: 15px;
    }
    
    .threat-card {
        background-color: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        margin-bottom: 16px;
        overflow: hidden;
        transition: border-color 0.2s;
    }
    
    .threat-card:hover {
        border-color: var(--accent);
    }
    
    .threat-summary {
        padding: 18px 24px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
    }
    
    .threat-summary-left {
        display: flex;
        align-items: center;
        gap: 15px;
        flex-grow: 1;
    }
    
    .threat-title {
        font-weight: 700;
        font-size: 15px;
        color: var(--text-primary);
    }
    
    .badge {
        font-size: 11px;
        font-weight: bold;
        padding: 4px 10px;
        border-radius: 12px;
        text-transform: uppercase;
        display: inline-block;
    }
    
    .badge-critical { background-color: rgba(239, 68, 68, 0.15); color: var(--color-critical); border: 1px solid var(--color-critical); }
    .badge-high { background-color: rgba(249, 115, 22, 0.15); color: var(--color-high); border: 1px solid var(--color-high); }
    .badge-medium { background-color: rgba(234, 179, 8, 0.15); color: var(--color-medium); border: 1px solid var(--color-medium); }
    .badge-low { background-color: rgba(34, 197, 94, 0.15); color: var(--color-low); border: 1px solid var(--color-low); }
    .badge-info { background-color: rgba(59, 130, 246, 0.15); color: var(--color-info); border: 1px solid var(--color-info); }
    
    .badge-accepted { background-color: rgba(16, 185, 129, 0.15); color: var(--color-accepted); border: 1px solid var(--color-accepted); }
    .badge-active { background-color: rgba(239, 68, 68, 0.15); color: var(--color-active); border: 1px solid var(--color-active); }
    
    .chevron {
        width: 20px;
        height: 20px;
        transition: transform 0.2s;
        stroke: var(--text-secondary);
        fill: none;
    }
    
    .threat-card.expanded .chevron {
        transform: rotate(180deg);
    }
    
    .threat-details {
        display: none;
        padding: 24px;
        border-top: 1px solid var(--border-color);
        background-color: rgba(15, 23, 42, 0.2);
    }
    
    .threat-card.expanded .threat-details {
        display: block;
    }
    
    .details-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 20px;
        margin-bottom: 24px;
    }
    
    .details-field {
        background-color: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 15px;
    }
    
    .details-field-label {
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
        color: var(--text-secondary);
        margin-bottom: 6px;
    }
    
    .details-field-value {
        font-size: 13px;
        word-break: break-word;
    }
    
    .full-width {
        grid-column: 1 / -1;
    }
    
    .reasoning-block {
        background-color: rgba(255, 255, 255, 0.01);
        border-left: 3px solid var(--accent);
        padding: 15px 20px;
        margin-top: 10px;
        border-radius: 0 6px 6px 0;
        font-size: 13px;
    }
    
    .reasoning-block h5 {
        margin-top: 12px;
        margin-bottom: 6px;
        color: var(--accent);
        font-size: 13px;
    }
    
    .reasoning-block h5:first-of-type {
        margin-top: 0;
    }
    
    .reasoning-list {
        margin: 8px 0;
        padding-left: 20px;
    }
    
    .reasoning-list li {
        margin-bottom: 4px;
    }
    
    code {
        background-color: rgba(255, 255, 255, 0.08);
        padding: 2px 6px;
        border-radius: 4px;
        font-family: 'Consolas', monospace;
        font-size: 12px;
    }
    
    footer {
        text-align: center;
        padding: 40px;
        color: var(--text-secondary);
        font-size: 12px;
        border-top: 1px solid var(--border-color);
        margin-top: 80px;
    }
    """
    
    # Javascript logic for collapsing items and dark mode toggling
    js_code = """
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const targetTheme = currentTheme === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', targetTheme);
        document.getElementById('theme-toggle').innerText = targetTheme === 'light' ? 'Dark Mode' : 'Light Mode';
    }
    
    function toggleThreat(cardElement) {
        cardElement.classList.toggle('expanded');
    }
    
    // Prevent collapsing when clicking on nested elements inside the header but not the header itself
    document.addEventListener("DOMContentLoaded", () => {
        const summaries = document.querySelectorAll('.threat-summary');
        summaries.forEach(s => {
            s.addEventListener('click', (e) => {
                const card = s.closest('.threat-card');
                toggleThreat(card);
            });
        });
    });
    """

    # Start building HTML content
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en" data-theme="dark">',
        "<head>",
        '    <meta charset="UTF-8">',
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"    <title>{html_title}</title>",
        '    <link rel="preconnect" href="https://fonts.googleapis.com">',
        '    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
        '    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Consolas&display=swap" rel="stylesheet">',
        f"    <style>{css_styles}</style>",
        "</head>",
        "<body>",
        "",
        "    <header>",
        '        <div class="logo-area">',
        f"            <h1>ThreatPilot Report: {html.escape(project.project_name)}</h1>",
        f'            <div class="meta-time">Generated on: {now}</div>',
        "        </div>",
        '        <button id="theme-toggle" class="theme-toggle-btn" onclick="toggleTheme()">Light Mode</button>',
        "    </header>",
        "",
        '    <div class="main-container">',
        "",
        '        <!-- Metrics Block -->',
        '        <div class="metrics-grid">',
        '            <div class="metric-card">',
        f'                <div class="metric-num">{total_threats}</div>',
        '                <div class="metric-lbl">Total Threats</div>',
        "            </div>",
        '            <div class="metric-card critical">',
        f'                <div class="metric-num">{critical_high_count}</div>',
        '                <div class="metric-lbl">Critical & High Risks</div>',
        "            </div>",
        '            <div class="metric-card accepted">',
        f'                <div class="metric-num">{accepted_risks}</div>',
        '                <div class="metric-lbl">Accepted Risks</div>',
        "            </div>",
        '            <div class="metric-card">',
        f'                <div class="metric-num">{pending_mitigations}</div>',
        '                <div class="metric-lbl">Pending Mitigations</div>',
        "            </div>",
        "        </div>",
        "",
        '        <div class="project-grid">',
        '            <div class="card">',
        '                <div class="card-title">1. Project Overview</div>',
        f"                <p>Security analysis report for the <strong>{html.escape(project.project_name)}</strong> threat model. The system was systematically analyzed using standard application security models (STRIDE methodology) to discover vulnerabilities, threats, and mitigations.</p>",
        "                <p>The structured risk assessments align discovered vulnerabilities with direct mitigations to allow the development team to quickly patch architectural and logic flaws.</p>",
        "            </div>",
        '            <div class="card">',
        '                <div class="card-title">Security Posture</div>',
        '                <ul class="meta-list">',
        '                    <li>',
        '                        <span class="meta-label">Industry Context:</span>',
        f'                        <span class="meta-value">{html.escape(project.prompt_config.industry_context or "General")}</span>',
        '                    </li>',
        '                    <li>',
        '                        <span class="meta-label">Security Posture:</span>',
        f'                        <span class="meta-value">{html.escape(project.prompt_config.security_posture)}</span>',
        '                    </li>',
        '                    <li>',
        '                        <span class="meta-label">Risk Preference:</span>',
        f'                        <span class="meta-value">{html.escape(project.prompt_config.risk_preference)}</span>',
        '                    </li>',
        '                </ul>',
        "            </div>",
        "        </div>",
        "",
        '        <div class="section-title">2. Detailed Findings Register</div>',
    ]

    if not threats:
        lines.append('        <div class="card" style="text-align: center; padding: 40px; color: var(--text-secondary);">')
        lines.append('            <p>No active threats or vulnerabilities identified in the project register.</p>')
        lines.append("        </div>")
    else:
        # Group threats by category
        grouped = defaultdict(list)
        for t in threats:
            grouped[t.category.value].append(t)
            
        for category, items in grouped.items():
            lines.append(f'        <div class="category-group">')
            lines.append(f'            <div class="category-header">{html.escape(category)} ({len(items)})</div>')
            
            for t in items:
                status_lbl = "ACCEPTED" if t.is_accepted_risk else "ACTIVE"
                status_class = "accepted" if t.is_accepted_risk else "active"
                severity = get_cvss_severity(t.cvss_score)
                severity_class = severity.lower()
                
                # Affected element/asset string
                elem_name, asset_name = t.resolve_affected_elements(project)
                affected_str = f"{elem_name} / {asset_name}" if elem_name != asset_name else elem_name
                
                # Chevron SVG
                chevron_svg = (
                    '<svg class="chevron" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">'
                    '<polyline points="6 9 12 15 18 9" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
                    '</svg>'
                )
                
                lines.append(f'            <div class="threat-card">')
                lines.append(f'                <div class="threat-summary">')
                lines.append(f'                    <div class="threat-summary-left">')
                lines.append(f'                        <span class="badge badge-{status_class}">{status_lbl}</span>')
                lines.append(f'                        <span class="badge badge-{severity_class}">{severity} ({t.cvss_score})</span>')
                lines.append(f'                        <span class="threat-title">{html.escape(t.title)}</span>')
                lines.append(f"                    </div>")
                lines.append(f"                    {chevron_svg}")
                lines.append(f"                </div>")
                
                lines.append(f'                <div class="threat-details">')
                lines.append(f'                    <div class="details-grid">')
                
                # Affected Architecture
                if affected_str:
                    lines.append(f'                        <div class="details-field">')
                    lines.append(f'                            <div class="details-field-label">Affected Architecture</div>')
                    lines.append(f'                            <div class="details-field-value">{html.escape(affected_str)}</div>')
                    lines.append(f"                        </div>")
                
                # Likelihood
                lines.append(f'                        <div class="details-field">')
                lines.append(f'                            <div class="details-field-label">Likelihood</div>')
                lines.append(f'                            <div class="details-field-value">{t.likelihood} / 5</div>')
                lines.append(f"                        </div>")
                
                # CVSS Vector
                if t.cvss_vector:
                    lines.append(f'                        <div class="details-field">')
                    lines.append(f'                            <div class="details-field-label">CVSS Vector</div>')
                    lines.append(f'                            <div class="details-field-value"><code>{html.escape(t.cvss_vector)}</code></div>')
                    lines.append(f"                        </div>")
                
                # MITRE ATT&CK
                if t.mitre_attack_id:
                    lines.append(f'                        <div class="details-field">')
                    lines.append(f'                            <div class="details-field-label">MITRE ATT&CK Mapping</div>')
                    lines.append(f'                            <div class="details-field-value">{html.escape(t.mitre_attack_id)} ({html.escape(t.mitre_attack_technique)})</div>')
                    lines.append(f"                        </div>")
                
                # Description
                lines.append(f'                        <div class="details-field full-width">')
                lines.append(f'                            <div class="details-field-label">Threat Description</div>')
                lines.append(f'                            <div class="details-field-value" style="white-space: pre-wrap;">{html.escape(t.description)}</div>')
                lines.append(f"                        </div>")
                
                # Vulnerabilities list (using the new vuln 'title' field!)
                v_ids = getattr(t, "vulnerability_ids", [])
                v_titles = []
                if v_ids and hasattr(project, "vulnerability_register"):
                    v_titles = [v.title for vid in v_ids if (v := project.vulnerability_register.get_vulnerability(vid))]
                
                if v_titles:
                    lines.append(f'                        <div class="details-field full-width">')
                    lines.append(f'                            <div class="details-field-label">Linked Vulnerabilities</div>')
                    lines.append(f'                            <div class="details-field-value">')
                    lines.append('                                <ul style="margin: 0; padding-left: 20px;">')
                    for v_title in v_titles:
                        lines.append(f"                                    <li>{html.escape(v_title)}</li>")
                    lines.append("                                </ul>")
                    lines.append("                            </div>")
                    lines.append(f"                        </div>")

                # Impact
                lines.append(f'                        <div class="details-field full-width">')
                lines.append(f'                            <div class="details-field-label">Security Business Impact</div>')
                lines.append(f'                            <div class="details-field-value" style="white-space: pre-wrap;">{html.escape(t.impact)}</div>')
                lines.append(f"                        </div>")

                # Mitigation Strategy
                lines.append(f'                        <div class="details-field full-width">')
                lines.append(f'                            <div class="details-field-label">Recommended Mitigation Strategy</div>')
                lines.append(f'                            <div class="details-field-value" style="white-space: pre-wrap;">{html.escape(t.mitigation)}</div>')
                lines.append(f"                        </div>")
                
                # Acceptance justification
                if t.is_accepted_risk and t.acceptance_justification:
                    lines.append(f'                        <div class="details-field full-width" style="border-color: var(--color-accepted);">')
                    lines.append(f'                            <div class="details-field-label" style="color: var(--color-accepted);">Risk Acceptance Justification</div>')
                    lines.append(f'                            <div class="details-field-value" style="white-space: pre-wrap;">{html.escape(t.acceptance_justification)}</div>')
                    lines.append(f"                        </div>")
                
                # Technical Reasoning (XAI)
                if t.reasoning:
                    md_reasoning = convert_reasoning_to_markdown(t.reasoning)
                    html_reasoning = _markdown_to_html(md_reasoning)
                    lines.append(f'                        <div class="details-field full-width">')
                    lines.append(f'                            <div class="details-field-label">Technical AI Reasoning (XAI)</div>')
                    lines.append(f'                            <div class="reasoning-block">{html_reasoning}</div>')
                    lines.append(f"                        </div>")

                lines.append(f"                    </div>") # details-grid
                lines.append(f"                </div>") # threat-details
                lines.append(f"            </div>") # threat-card
            
            lines.append("        </div>") # category-group
            
    lines.extend([
        "    </div>",
        "",
        "    <footer>",
        f"        <p>ThreatPilot Security Report &copy; {datetime.now().year}.</p>",
        "    </footer>",
        "",
        f"    <script>{js_code}</script>",
        "</body>",
        "</html>",
    ])
    
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
