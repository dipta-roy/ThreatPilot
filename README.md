<div align="center">
  <img src="./threatpilot/resources/app-icon.png" alt="ThreatPilot Logo" width="150" />
  
  # ThreatPilot
  
  **Advanced AI-Driven Threat Modeling for Security Architects and Engineers.**
</div>

<br/>

**ThreatPilot** automates the extraction of architectural components from diagrams, converts them into formal Data Flow Diagrams (DFDs), and performs automated STRIDE and LINDDUN-based risk assessments using large language models (LLMs). Built on a robust desktop-and-web hybrid architecture, it bridges the gap between fast-paced engineering and rigorous security compliance.

---

## Table of Contents
- [Core Capabilities](#core-capabilities)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
- [Security & Privacy](#security--privacy)
- [Architecture Stack](#architecture-stack)
- [Trust & Verification](#trust--verification)

---

## Core Capabilities

- **AI Vision Analysis:** Identifies architectural components, trust boundaries, and communication flows directly from images.
- **Deterministic Math Engine:** Resolves risk scores deterministically using an algorithmic Tri-Graph traversal before AI inference.
- **Multi-Agent Orchestrator:** Implements a strict 5-agent pipeline (Threat, Mitigation, Evidence, Compliance, Reporting) for resilient JSON extraction.
- **CI/CD Automation:** First-class CLI and FastAPI backend for executing headless threat models in deployment pipelines.
- **Real-Time Web Designer:** Drag-and-drop architecture designer with instant sync to your desktop client.

---

## Key Features

### Intelligent Architecture Detection
- **Formal DFD Conversion**: Transforms logical architectural elements into industry-standard Data Flow Diagrams with distinct Process, Data Store, External Entity, and Data Flow nodes.
- **Zero-Dependency Detection**: Traditional Computer Vision (OpenCV) is replaced by highly accurate AI-driven detection, reducing application weight by 80%.
- **Segmented Analysis**: Intelligently segments large architectures into batches to respect model token limits without losing structural context.

### Streamlined AI Threat Analysis
- **Attacker-Centric True Threat Modeling**: Evaluates systems purely on attacker behaviors rather than raw missing controls, enforcing canonical threat profiles.
- **Evidence vs. Assumption Engine**: Eliminates AI hallucinations by strictly segregating findings supported by architectural evidence from speculative assumptions.
- **Deterministic Traceability**: Provides a full `evidence_traversal_path` and `confidence` score for every finding to make AI outputs fully auditable.
- **Incremental Traversal Engine**: ThreatPilot selectively analyzes downstream architectural changes instead of the entire topology, drastically reducing generation time for large architectures.
- **Contextual UI Generation**: Right-click components in either the Desktop or Web interface to trigger localized generation of Threats, Mitigations, or Abuse Cases.
- **Node Analysis States**: Native integration of analysis states tracks component lifecycles to guarantee accurate diffs and compliance checks.
- **Context-Aware Prompts:** Generates structured, industry-contextualized prompts for LLMs.
- **MITRE ATT&CK® Mapping:** Automatically maps identified threats to specific MITRE ATT&CK techniques, aligning risk with defensive operations.
- **Map-Reduce Batch Processing**: Implements recursive background batching to deduplicate and consolidate hundreds of mitigation requirements seamlessly.

### Risk Assessment & Controls
- **CVSS v3.1 Scoring**: Built-in calculator determines base vulnerability scores with automatic severity categorization.
- **CVSS Modification Rationale**: Track manual adjustments to AI-suggested CVSS vectors with dedicated rationale fields to maintain auditability and justification for overrides.
- **Decoupled Vulnerability Registry**: Manage security flaws independently from threats via a global registry for standardized remediation tracking.
- **Live Risk Counters**: Architecture elements feature real-time, non-editable risk badges that dynamically sync with the active Threat Register.

### Professional Reporting & Export
- **Comprehensive Markdown Reports**: Generates deep-dive narrative reports including executive summaries and detailed threat registers.
- **Lightweight Excel Exports**: Custom-built, bloat-free Excel generation (`openpyxl`) for 7-tab GRC workbooks.
- **AI-Reviewed Mitigation Requirements**: Automatically reviews and deduplicates mitigations, mapping them to affected components and generating testing criteria.
- **Git-Optimized Storage**: Project data is partitioned into clean JSON sidecars (`architecture.json`, `threats.json`, etc.) enabling human-readable diffs in version control.

---

## Getting Started

### Prerequisites
- **Python 3.11+**
- **Local LLM** (Ollama recommended) or a **Google Gemini API Key**.
- **Recommended Models**: `qwen2.5-vl` (Ollama) or `gemini-3.1-flash-lite` (Google).

### Installation
```bash
# Clone the repository
git clone https://github.com/dipta-roy/ThreatPilot.git
cd ThreatPilot

# Install lightweight dependencies
pip install -r requirements.txt
```

### Running the Desktop Application

**Using Python / Scripts:**
- On **Windows**, you can double-click or run `run_threatpilot.bat`.
- On **Linux/macOS**, you can run `./run_threatpilot.sh`.
- Alternatively, you can start it manually with `python main.py`.

**Using the Windows Installer (No Python Required):**
For a completely standalone experience on Windows, download the pre-packaged `.msi` installer from the [Releases](https://github.com/dipta-roy/ThreatPilot/releases) page. Install it, and run ThreatPilot directly from your Start Menu without installing Python.

### Troubleshooting Mac/Linux Permissions
If you encounter permission errors (e.g., Access Denied) while running the scripts on Mac or Linux, **do not use `chmod 777`**. Instead, run these commands in your terminal from the ThreatPilot folder to fix ownership and quarantine flags:
```bash
sudo chown -R $USER:staff .
xattr -dr com.apple.quarantine .
chmod +x run_threatpilot.sh
```

---

## Security & Privacy

### API Key Management & Encryption
- **PBKDF2 Key Derivation**: Master keys are derived using PBKDF2 with 100,000 iterations and SHA-256.
- **AES-128 Encryption**: Sensitive API keys are encrypted using Fernet (AES-CBC) before being stored.
- **Secure Transmission**: Uses the `x-goog-api-key` header for Gemini requests, preventing key exposure in URL logs.

### Workspace Sharing Security
ThreatPilot allows you to host the web-based visual designer locally or share it securely across your local network. Strict controls are enforced:
- **TLS Encryption**: Network traffic can be secured via TLS (HTTPS) using self-signed certificates generated directly within the app.
- **8-Digit PIN Authentication**: Shared sessions require an 8-digit secure PIN, protecting against unauthorized network access and brute-force attempts.
- **Strict Session Management**: Authentication relies on cryptographically secure session cookies enforcing `HttpOnly`, `SameSite=Strict`, and `Secure` attributes, preventing XSS-based cookie theft.
- **Instant Access Revocation**: Stopping a shared session instantly clears all backend sessions. The React SPA actively monitors its connection and forcefully locks and wipes the browser screen upon receiving a `401 Unauthorized` response or losing connection to the host, ensuring data is never left lingering.

### Data Privacy & Safe Interaction
- **Local Analysis Support**: Using **Ollama** ensures your architecture diagrams and threat models never leave your local machine.
- **Injection Protection**: XML-style delimiters and metadata sanitization prevent prompt-injection attacks.
- **Masked Logs**: Application logs and error traces automatically redact identified API keys and sensitive credentials.

---

## Architecture Stack
- **UI Framework**: PySide6 (Qt for Python).
- **Web-Based Designer**: React, TypeScript, React Flow, and Tailwind CSS.
- **Local Web Server**: Native Python `http.server` running on a background thread.
- **Data & Validation**: Pydantic (v2).
- **Exporting**: OpenPyXL.
- **Build System**: cx_Freeze optimized for lean MSI installers (~200MB).

*Detailed developer documentation can be found in the [Architecture Overview](./ARCHITECTURE.md).*

---

## Trust & Verification

Download the Code Verification Certificate: [Dipta Roy - Code Verification Certificate](https://github.com/dipta-roy/dipta-roy.github.io/blob/main/downloads/Code%20Verifying%20Certificates.zip).

**How to Install the Certificate:**
1. Download and extract the certificate from the link above.
2. Right-click `Signed_By_Dipta_CodeSigningPublicKey.cer` → **Install Certificate**.
3. Select **Local Machine** (requires admin privileges).
4. Choose **Place all certificates in the following store**.
5. Click **Browse** → Select **Trusted Root Certification Authorities**.
6. Click **Next** → **Finish**.

**Verify Application Authenticity:**
1. Right-click on the installer (e.g. `ThreatPilot-3.2.0-win64.msi`) and select **Properties**.
2. Go to the **Digital Signatures** tab.
3. Select "Signed_By_Dipta" from the Embedded Signatures list, then click **Details**.
4. In the General tab, you should see the message: *"This digital signature is OK."*

Once verified, you may safely run the installer to set up ThreatPilot!