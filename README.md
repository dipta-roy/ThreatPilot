# ThreatPilot

**ThreatPilot** is an advanced, AI-driven threat modeling application designed specifically for cyber security architects and engineers. It automates the extraction of architectural components from diagrams, converts them into formal Data Flow Diagrams (DFDs), and performs automated STRIDE-based risk assessments using large language models (LLMs).

---

## ✨ Key Features

### 🔍 1. Intelligent Architecture Detection
- **Computer Vision Analysis**: Uses OpenCV to automatically identify architectural components, trust boundaries, and communication flows from images.
- **Integrated OCR**: Extracts text labels from diagram elements using Tesseract-OCR, mapping them to logical system components.
- **Formal DFD Conversion**: Transforms logical architectural elements into industry-standard Data Flow Diagrams (DFD) with distinct **Process**, **Data Store**, and **External Entity** nodes.

### 🤖 2. AI-Powered Threat Analysis
- **Context-Aware Prompts**: Generates structured, industry-contextualized prompts for LLMs to perform detailed STRIDE analysis.
- **Flexible Backend Support**: Interfaces with local **Ollama** instances or external **REST APIs** (OpenAI-compatible) for highly private or highly scalable analysis.
- **Structured Risk Identifiers**: Automatically generates threat titles, descriptions, impacts, and remediation guidance in a parsed JSON format.

### 📊 3. Risk Assessment & Controls
- **CVSS v3.1 Scoring**: Built-in calculator to determine base vulnerability scores, complete with severity categorization (Low-Critical).
- **Framework Mapping**: Automatically maps identified threats to established security controls from **NIST SP 800-53** and **OWASP Top 10**.
- **Asset Tagging**: Explicitly tag **High Value Assets (HVA)** to prioritize critical system exposures during analysis.

### 📝 4. Professional Reporting & Export
- **Comprehensive Markdown Reports**: Generates deep-dive narrative reports including methodology and risk summaries.
- **Tabular Excel Exports**: Full project threat register exported for external GRC or Excel-based management.
- **Annotated Diagram Overlays**: Export your architectural diagrams with high-fidelity vector overlays of all identified security boundaries and flows.

### 🛠️ 5. Advanced Workflow Management
- **Manual Adjustments**: Full support for manual threat entry, deletion, and property editing for human-in-the-loop validation.
- **Risk Acceptance**: Track and document accepted risks with clear rationales directly in the project metadata.
- **Project Snapshots**: Built-in versioning system to create point-in-time archives of your analysis progress.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+**
- **Local LLM** (Ollama recommended) or an **API Key** for external providers (Gemini, Claude, OpenAI).
- **Tesseract OCR**: Required for automatic text extraction from diagrams. If not installed, ThreatPilot will safely fall back to naming discovered components generically (e.g., `"Box @ 120,40"`).
  - **Windows Users**: Download and install the binaries from the [UB-Mannheim Tesseract Wiki](https://github.com/UB-Mannheim/tesseract/wiki). Ensure you add `tesseract.exe` to your system `PATH`.
  - **Linux/macOS Users**: Install via your native package manager (e.g., `sudo apt install tesseract-ocr` or `brew install tesseract`).

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
# Launch the ThreatPilot GUI
python main.py
```

---

## 🏗️ Architecture Stack
- **Core UI**: PySide6 (Qt)
- **Data Modelling**: Pydantic BaseModel (v2)
- **Computer Vision**: OpenCV 4.x & Numpy
- **Data Processing**: Pandas
- **Communication**: HTTPX (Asynchronous REST interaction)

---

## 🎨 Design Philosophy
ThreatPilot is built on a **Modular Architecture**. Each core domain—Detection, Risk, AI, and Export—is isolated in its own package. This ensures the application is extremely extensible, allowing for future support of new AI providers, additional security frameworks, or custom detection algorithms.

---

## 📑 License
© 2026 ThreatPilot Development Team. All rights reserved. Registered under the MIT License.
