import pandas as pd
from pathlib import Path
from typing import List, Optional
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Alignment
from openpyxl.drawing.image import Image

from threatpilot.core.project_manager import Project
from threatpilot.risk.cvss_calculator import get_cvss_severity

def export_to_excel(project: Project, output_path: str | Path) -> None:
    """Generate a high-fidelity 7-tab Risk Assessment Excel workbook."""
    
    def sanitize_excel(val):
        if isinstance(val, str) and val.startswith(('=', '+', '-', '@')):
            return f"'{val}"
        return val or ""

    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        # --- TAB 1: System Description ---
        sys_desc_data = {
            "Field": ["Project Name", "Created At", "Industry Context", "Security Posture", "Risk Preference"],
            "Value": [
                sanitize_excel(project.project_name), 
                project.created_at, 
                sanitize_excel(project.prompt_config.industry_context or "General"),
                sanitize_excel(project.prompt_config.security_posture),
                sanitize_excel(project.prompt_config.risk_preference)
            ]
        }
        pd.DataFrame(sys_desc_data).to_excel(writer, sheet_name="System Description", index=False)

        # --- TAB 2: Architecture Diagram ---
        # Create empty sheet first
        wb = writer.book
        ws_diag = wb.create_sheet("Architecture Diagram")
        if project.diagrams:
             try:
                 diag = project.diagrams[0]
                 img_path = Path(project.project_path) / diag.file_path
                 if img_path.exists():
                     img = Image(str(img_path))
                     ws_diag.add_image(img, 'B2')
             except Exception as e:
                 ws_diag["B2"] = f"Image could not be embedded: {e}"
        else:
             ws_diag["B2"] = "No architecture diagram provided."

        # --- TAB 3: System Elements ---
        elements = []
        for c in project.components:
             elements.append({
                 "Element Name": sanitize_excel(c.name),
                 "Classification": sanitize_excel(c.element_classification),
                 "Description": sanitize_excel(f"Detected {c.element_classification} in architecture blueprint.")
             })
        pd.DataFrame(elements).to_excel(writer, sheet_name="System Elements", index=False)

        # --- TAB 4: System Assets ---
        assets = []
        for c in project.components:
             assets.append({
                 "Asset Name": sanitize_excel(c.name),
                 "Asset Classification": sanitize_excel(c.asset_classification),
                 "Description": sanitize_excel(f"Identified {c.asset_classification} asset for security analysis.")
             })
        pd.DataFrame(assets).to_excel(writer, sheet_name="System Assets", index=False)

        # --- TAB 5: STRIDE Threats ---
        threats_stride = []
        for t in project.threat_register.threats:
             threats_stride.append({
                 "Category": sanitize_excel(t.category.value if hasattr(t.category, 'value') else t.category),
                 "Threat Title": sanitize_excel(t.title),
                 "Description": sanitize_excel(t.description)
             })
        pd.DataFrame(threats_stride).to_excel(writer, sheet_name="STRIDE Threats", index=False)

        # --- TAB 6: Vulnerabilities ---
        vulns = []
        for t in project.threat_register.threats:
             if t.vulnerabilities:
                 vulns.append({
                     "Threat Source": sanitize_excel(t.title),
                     "Vulnerabilities": sanitize_excel(t.vulnerabilities)
                 })
        pd.DataFrame(vulns).to_excel(writer, sheet_name="Vulnerabilities", index=False)

        # --- TAB 7: Risk Assessment (The Detailed Tab) ---
        risk_data = []
        for i, t in enumerate(project.threat_register.threats):
            severity = get_cvss_severity(t.cvss_score)
            risk_data.append({
                "Risk ID": i + 1,
                "Element Component Name": sanitize_excel(t.affected_element or t.affected_components or "N/A"),
                "Asset Component Name": sanitize_excel(t.affected_asset or t.affected_components or "N/A"),
                "Threats": sanitize_excel(t.title),
                "Vulnerabilities": sanitize_excel(t.vulnerabilities),
                "Description": sanitize_excel(t.description),
                "Impact": sanitize_excel(t.impact),
                "CVSS Vector (3.1)": t.cvss_vector or "N/A",
                "Likelihood": f"{t.likelihood}/5",
                "Severity": f"{severity} ({t.cvss_score})",
                "Mitigation Strategy": sanitize_excel(t.mitigation)
            })
        
        df_risk = pd.DataFrame(risk_data)
        df_risk.to_excel(writer, sheet_name="Risk Assessment", index=False)
        
        # Apply Styling to Tab 7
        ws_risk = writer.sheets["Risk Assessment"]
        
        # Severity row formatting (Col 10 - indexed locally by col J)
        # We find the 'Severity' col index
        sev_col_idx = 10 # J
        
        fill_crit = PatternFill(start_color="7B1E1E", end_color="7B1E1E", fill_type="solid")
        fill_high = PatternFill(start_color="CC0000", end_color="CC0000", fill_type="solid")
        fill_med = PatternFill(start_color="FFBB33", end_color="FFBB33", fill_type="solid")
        fill_low = PatternFill(start_color="33B5E5", end_color="33B5E5", fill_type="solid")
        
        white_font = Font(color="FFFFFF", bold=True)
        black_font = Font(color="000000", bold=True)

        for row_idx, row in enumerate(ws_risk.iter_rows(min_row=2, max_row=ws_risk.max_row, min_col=10, max_col=10)):
            cell = row[0]
            val = str(cell.value).upper()
            if "CRITICAL" in val:
                cell.fill = fill_crit
                cell.font = white_font
            elif "HIGH" in val:
                cell.fill = fill_high
                cell.font = white_font
            elif "MEDIUM" in val:
                cell.fill = fill_med
                cell.font = black_font
            elif "LOW" in val:
                cell.fill = fill_low
                cell.font = black_font

        # --- TAB 8: Visual Risk Matrix (The Heat Map) ---
        ws_matrix = wb.create_sheet("Visual Risk Matrix")
        
        # Grid Headers
        ws_matrix["A1"] = "Likelihood \ Impact"
        ws_matrix["A1"].font = Font(bold=True)
        
        impact_labels = ["Low (1)", "Minor (2)", "Mid (3)", "Major (4)", "Crit (5)"]
        likelihood_labels = ["Certain (5)", "Likely (4)", "Possible (3)", "Unlikely (2)", "Rare (1)"]
        
        for i, label in enumerate(impact_labels):
            ws_matrix.cell(row=1, column=i+2, value=label).font = Font(bold=True)
            ws_matrix.cell(row=1, column=i+2).alignment = Alignment(horizontal="center")
            
        for i, label in enumerate(likelihood_labels):
            ws_matrix.cell(row=i+2, column=1, value=label).font = Font(bold=True)

        # Build 5x5 Counts
        matrix_counts = {} # (row_idx_0_to_4, col_idx_0_to_4)
        for t in project.threat_register.threats:
            impact_score = 1
            if t.cvss_score >= 9.0: impact_score = 5
            elif t.cvss_score >= 7.0: impact_score = 4
            elif t.cvss_score >= 4.0: impact_score = 3
            elif t.cvss_score >= 2.0: impact_score = 2
            
            row_idx = 5 - t.likelihood
            col_idx = impact_score - 1
            matrix_counts[(row_idx, col_idx)] = matrix_counts.get((row_idx, col_idx), 0) + 1

        # Render 5x5 Grid with Heat Colors
        for r in range(5):
            for c in range(5):
                count = matrix_counts.get((r, c), 0)
                cell = ws_matrix.cell(row=r+2, column=c+2, value=count if count > 0 else "")
                cell.alignment = Alignment(horizontal="center", vertical="center")
                
                # Determine colors (mirroring RiskMatrixDialog)
                likelihood = 5 - r
                impact = c + 1
                risk_score = likelihood * impact
                
                if risk_score >= 15: bg = "8B0000"; ft = "FFFFFF" # Critical
                elif risk_score >= 10: bg = "D73A49"; ft = "FFFFFF" # Major
                elif risk_score >= 6:  bg = "D29922"; ft = "000000" # Warning
                elif risk_score >= 3:  bg = "30363D"; ft = "FFFFFF" # Mid
                else: bg = "238636"; ft = "FFFFFF" # Low
                
                cell.fill = PatternFill(start_color=bg, end_color=bg, fill_type="solid")
                cell.font = Font(color=ft, bold=True if count > 0 else False)

        # Adjust matrix column widths
        ws_matrix.column_dimensions["A"].width = 15
        for c in range(2, 7):
            ws_matrix.column_dimensions[chr(64+c)].width = 12

        # Auto-adjust column widths for readability in all other sheets
        for ws in wb.worksheets:
             if ws.title == "Visual Risk Matrix": continue
             for col in ws.columns:
                 max_length = 0
                 column = col[0].column_letter
                 for cell in col:
                     try:
                         val_str = str(cell.value)
                         if len(val_str) > max_length:
                             max_length = len(val_str)
                     except (ValueError, TypeError):
                         pass
                     except Exception:
                         pass
                 adjusted_width = (max_length + 2)
                 ws.column_dimensions[column].width = min(adjusted_width, 60) # cap at 60
