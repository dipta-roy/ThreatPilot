![ThreatPilot](./threatpilot/resources/app-icon.png)

# ThreatPilot

**ThreatPilot** is an advanced, AI-driven threat modeling application designed specifically for cyber security architects and engineers. It automates the extraction of architectural components from diagrams, converts them into formal Data Flow Diagrams (DFDs), and performs automated STRIDE-based risk assessments using large language models (LLMs).

---

## Key Features

### 1. Intelligent Architecture Detection
- **AI Vision Analysis**: Automatically identify architectural components, trust boundaries, and communication flows from images using multimodal AI (Recommended Qwen2.5-VL or Gemini 3.1-Flash-Lite).
- **Formal DFD Conversion**: Transforms logical architectural elements into industry-standard Data Flow Diagrams (DFD) with distinct **Process**, **Data Store**, **External Entity**, and **Data Flow** nodes.
- **Zero-Dependency Detection**: Traditional Computer Vision (OpenCV) has been replaced by more accurate AI-driven detection, reducing application size by 80%.

### 2. Streamlined AI Threat Analysis
- **Context-Aware Prompts**: Generates structured, industry-contextualized prompts for LLMs to perform detailed **STRIDE** analysis.
- **Optimized Provider Support**: Focused support for local **Ollama** instances (for privacy) and high-performance **Google Gemini** endpoints.
- **Segmented Analysis**: Automatically handles large-scale architectures by segmenting diagrams into batches to respect model token limits while maintaining context.

### 3. Risk Assessment & Controls
- **CVSS v3.1 Scoring**: Built-in calculator to determine base vulnerability scores with automatic severity categorization (Low-Critical).
- **Interactive Risk Matrix**: Visualize your system's risk profile through a dynamic Likelihood vs. Impact matrix.
- **High-Fidelity Tracking**: Manage threats with a full-featured Threat Ledger, supporting acceptance, mitigation status, and manual overrides.

### 4. Professional Reporting & Export
- **Comprehensive Markdown Reports**: Generates deep-dive narrative reports including methodology, executive summaries, and detailed threat registers.
- **Lightweight Excel Exports**: Custom-built Excel generation using `openpyxl`, ensuring high-fidelity 7-tab GRC workbooks without the bloat of heavy data libraries.
- **Architecture Export**: Save your modeled architecture as structured JSON or export annotated diagrams.

### 5. Advanced UX & Workflow
- **Modern UI**: A premium desktop application built with **PySide6**, featuring **Dark** and **Light** theme support.
- **Undo/Redo System**: Full state management for editing components, flows, and trust boundaries.
- **Quick Start Wizard**: Onboarding experience for new users to bootstrap their first project in seconds.
- **Human-in-the-Loop**: Manually refine detected components, add custom threats, or override AI-generated assessments via the Project Explorer.

---

## Getting Started

### Prerequisites
- **Python 3.11+**
- **Local LLM** (Ollama recommended) or a **Google Gemini API Key**.
- **Recommended Models**: `qwen2.5vl:3b` or `qwen2.5vl:7b` (for Ollama) and `gemini-3.1-flash-lite-preview` or `gemini-2.0-flash`.

### Installation
```bash
# Clone the repository
git clone https://github.com/dipta-roy/ThreatPilot.git
cd ThreatPilot

# Install lightweight dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
python main.py
```

---

## Architecture Stack
- **UI Framework**: PySide6 (Qt for Python).
- **Data & Validation**: Pydantic (v2).
- **AI Orchestration**: Custom asynchronous interface supporting Ollama and Gemini.
- **Networking**: HTTPX.
- **Exporting**: OpenPyXL (Native Excel generation).

---

## Security & Privacy

### API Key Management & Encryption
ThreatPilot implements industry-standard protection for your credentials:
- **PBKDF2 Key Derivation**: Master keys are derived using **PBKDF2 with 100,000 iterations** and SHA-256.
- **Hardware-Bound & Session Keys**: Supports both OS-native **Credential Manager** (via `keyring`) for usability and the `THREATPILOT_MASTER_KEY` environment variable for high-security, session-based key rotation.
- **AES-128 Encryption**: Sensitive API keys are encrypted using **Fernet (AES-CBC)** before being stored in `config.env`.

### AI Interaction Security
- **Injection Protection**: XML-style delimiters and metadata sanitization prevent "jailbreaking" through architectural descriptions or custom prompts.
- **SSRF Defense**: Strict validation of AI endpoint URLs to block access to internal metadata services and private network ranges.
- **Secure Transmission**: Uses the `x-goog-api-key` header for Gemini requests, preventing key exposure in URL logs or proxy history.

### Data Privacy
- **Local Analysis**: Using the **Ollama** provider ensures that your architecture diagrams and threat models never leave your local machine.
- **Privacy Acknowledgement**: Mandatory user consent before transmitting any data to cloud AI providers (e.g., Gemini).
- **Masked Logs**: Application logs and error traces automatically redact identified API keys and sensitive credentials.

---

## Design Philosophy
ThreatPilot is built on a **Modular Domain-Driven Architecture**. Each core package—`ai`, `detection`, `risk`, `core`, and `ui`—is isolated, making it easy to add new AI backends or export formats without side effects.

Detailed developer documentation: [Architecture Overview](./ARCHITECTURE.md).

---
