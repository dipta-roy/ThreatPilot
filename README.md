# ThreatPilot

**ThreatPilot** is an advanced, AI-driven threat modeling application designed specifically for cyber security architects and engineers. It automates the extraction of architectural components from diagrams, converts them into formal Data Flow Diagrams (DFDs), and performs automated STRIDE-based risk assessments using large language models (LLMs).

---

## ✨ Key Features

### 🔍 1. Intelligent Architecture Detection
- **Computer Vision Analysis**: Automatically identify architectural components, trust boundaries, and communication flows from images.
- **Integrated OCR**: Extracts text labels from diagram elements using **AI**, mapping them to logical system components.
- **Formal DFD Conversion**: Transforms logical architectural elements into industry-standard Data Flow Diagrams (DFD) with distinct **Process**, **Data Store**, **External Entity**, and **Data Flow** nodes.

### 🤖 2. AI-Powered Threat Analysis
- **Context-Aware Prompts**: Generates structured, industry-contextualized prompts for LLMs to perform detailed **STRIDE** analysis.
- **Multi-Provider Support**: Seamlessly switch between local **Ollama** instances or high-performance external providers like **Google Gemini**, **Anthropic Claude**, and OpenAI-compatible endpoints.
- **Segmented Analysis**: Automatically handles large-scale architectures by segmenting diagrams into batches to respect model token limits while maintaining context.
- **Vision-to-Architecture**: Utilize multimodal LLMs (like Qwen2.5-VL or Gemini 1.5 Flash) to directly "see" and bootstrap architecture models from diagram images.

### 📊 3. Risk Assessment & Controls
- **CVSS v3.1 Scoring**: Built-in calculator to determine base vulnerability scores with automatic severity categorization (Low-Critical).
- **Security Control Mapping**: (In-development) Maps identified threats to established security controls from **NIST SP 800-53** and **OWASP Top 10**.
- **Interactive Risk Matrix**: Visualize your system's risk profile through a dynamic Likelihood vs. Impact matrix.

### 📝 4. Professional Reporting & Export
- **Comprehensive Markdown Reports**: Generates deep-dive narrative reports including methodology, executive summaries, and detailed threat registers.
- **Tabular Excel Exports**: High-fidelity 7-tab Risk Assessment workbooks for GRC integration or manual management.
- **Architecture Export**: Save your modeled architecture as structured JSON or export annotated diagrams.

### 🛠️ 5. Advanced Workflow Management
- **Full-Featured GUI**: A modern, dark-themed desktop application built with **PySide6**.
- **Human-in-the-Loop**: Manually refine detected components, add custom threats, or override AI-generated assessments.
- **Project Versioning**: Built-in manager to track changes and maintain a history of your threat model's evolution.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+**
- **Local LLM** (Ollama recommended) or an **API Key** for external providers (Tested with Gemini).
- **Recommended Models** Qwen2.5-VL or Qwen3-VL or Gemini-3-flash-preview

### Installation
```bash
# Clone the repository
git clone https://github.com/dipta-roy/ThreatPilot.git
cd ThreatPilot

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
python main.py
```

---

## 🏗️ Architecture Stack
- **UI Framework**: PySide6 (Qt for Python)
- **Data & Validation**: Pydantic (v2)
- **AI Orchestration**: Custom provider interface supporting Ollama, Gemini, Claude, and Generic REST.
- **Image Processing**: OpenCV, Pillow (PIL).
- **Networking**: HTTPX (Asynchronous I/O).
- **Exporting**: Pandas, OpenPyXL.

---

## 🔒 Security & Privacy

### API Key Management
ThreatPilot prioritizes the security of your credentials:
- **AES-128 Encryption**: API keys are encrypted using **Fernet** before storage.
- **Hardware-Bound Keys**: The master encryption key is stored in your OS's native **Credential Manager** (Windows Credential Manager, macOS Keychain, etc.) via `keyring`.

### Data Privacy
- **Local Analysis**: Using the **Ollama** provider ensures that your architecture diagrams and threat models never leave your local machine.
- **Masked Logs**: Application logs automatically redact identified API keys to prevent accidental exposure.

---

## 🎨 Design Philosophy
ThreatPilot is built on a **Modular Domain-Driven Architecture**. Each core package—`ai`, `detection`, `risk`, `core`, and `ui`—is isolated, making it easy to add new AI backends, detection algorithms, or export formats without side effects.

---