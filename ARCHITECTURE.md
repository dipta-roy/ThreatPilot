# ThreatPilot Architecture Overview

ThreatPilot is an advanced AI-driven threat modeling application designed to help security engineers and architects analyze systems based on data flow diagrams (DFDs). It uses Large Language Models (LLMs) to automatically identify threats following the STRIDE methodology and prioritize them using risk assessment frameworks.

---

## High-Level System Architecture

The application follows a modular, layered architecture that separates presentation (UI) from core logic and AI integration.

```mermaid
graph TD
    subgraph "User Interface (Desktop & Web)"
        MW[MainWindow] --> DC[Diagram Canvas]
        MW --> PP[Properties Panel]
        MW --> TP[Threat Panel]
        MW --> RA[Risk Assessment]
        MW --> PE[Project Explorer]
        MW -- "Launches Browser" --> WD[Web Architecture Designer]
    end

    subgraph "Core Logic & Infrastructure"
        PM[Project Manager] --> DM[Domain Models]
        PM --> TM[Threat Model]
        PM --> VR[Vulnerability Register]
        US[Undo System] --> MW
        DFD[DFD Converter]
        DS[Designer Server] --> PM
    end

    subgraph "AI Analysis Engine"
        TA[Threat Analyzer] --> PB[Prompt Builder]
        TA --> AP[AI Providers]
        TA --> RP[Response Parser]
    end

    subgraph "Data & Security"
        JSON[(Project JSON)]
        ENV[config.env]
        CRY[Crypto Utils]
        CON[Constants & Paths]
    end

    DC <--> PM
    WD <--> DS
    PM <--> JSON
    MW <--> TA
    AP <--> ENV
    ENV <--> CRY
    MW <--> CON
```

---

## Core Layers and Components

### 1. User Interface (UI) Layer
The UI is built using Python and PySide6, providing a desktop-native experience for complex modeling tasks.
- **MainWindow**: The central hub that orchestrates the layout, menus, and global state transitions.
- **Diagram Canvas**: A specialized component for drawing and interacting with DFD elements (Components, Flows, Trust Boundaries).
- **Properties Panel**: A context-aware side dock for editing attributes of selected architectural elements.
- **Threat Panel**: A tabular view of all identified threats with filtering and prioritization controls.
- **Risk Assessment Suite**: Includes interactive CVSS 3.1 calculators and a Risk Matrix visualization for severity analysis.

### 2. Core Engine
Handles the underlying logic of threat modeling and state management.
- **Domain Models**: Pydantic-based schemas for architectural elements (Entity, Process, Data Store, Flow).
- **Threat Model**: Implements both **STRIDE** (Security) and **LINDDUN** (Privacy) categorization, CVSS 3.1 scoring, and **MITRE ATT&CK** technique mapping.
- **Vulnerability Register**: A global repository of identified security flaws. Decouples technical vulnerabilities from high-level threats, allowing for standardized remediation tracking across multiple elements.
- **Project Manager**: Orchestrates project lifecycles using a **Multi-File Persistence** strategy (partitioning data into `project.json`, `architecture.json`, `threats.json`, and `vulnerabilities.json`).
- **Undo System**: Uses `QUndoStack` for multi-action undo/redo capabilities.

### 3. Web Architecture Designer Layer
An alternative interactive workspace built as a React single page application (`f:/ThreatPilot/designer`) and integrated via a standard library web server.
- **Designer Server (`designer_server.py`)**: A lightweight multi-threaded HTTP server built on Python's native `http.server`. It hosts the visual designer frontend assets and exposes `/api/project` REST endpoints to read/write diagram changes, as well as `/api/project/image` to save screenshot uploads.
- **React Flow Canvas**: A modern interactive canvas using Tailwind CSS and React Flow with full support for light/dark themes, trust boundary containment/resizing, and instant file sync. Component nodes render a dynamic, pulsing red badge showing the active threat count.
- **Properties Panel**: A mouse-resizable sidebar dock (260px - 800px) that enables fully selectable and copyable text container layouts for easy copy-pasting of metadata.
- **Workspace Screenshot Capture**: A toolbar control that dynamically imports `html-to-image` at runtime, serializes the viewport, downloads the JPEG client-side, and POSTs it to the backend to be persisted as the project's default `architecture.jpg` design.
- **Validation & Export Panels**: Generates real-time structural warnings, ASCII diagram previews, and Mermaid code exports directly in the web UI.
- **Network Sharing & PIN Session Security**: Allows users to toggle "Host Architecture Workspace" between **Shared (Yes/No)** modes. If "Yes" is toggled, the server binds to `0.0.0.0` (accessible from any computer on the local network) and generates a random 6-digit PIN. Remote users are forced to authenticate via a dedicated `/auth` login portal using the PIN, which stores a cryptographically safe session cookie (`threatpilot_session`) validated on subsequent API calls. Local loopback (`127.0.0.1`) accesses automatically bypass authentication. If toggled "No", the server binds strictly to `127.0.0.1`.
- **Manual Data Entry & Modeling Control**: Comprehensive modals (Add Threat, Add Risk, Add Vulnerability, Add Mitigation) allow full manual overrides with integrated real-time CVSS v3.1 calculators inside the browser.

### 4. AI Analysis Engine
A sophisticated pipeline that transforms architectural diagrams into structured security insights.
- **Threat Analyzer**: The primary orchestrator that segments large architectures to fit within LLM context windows. It integrates the **XAI Reasoning engine** across all tables (Threats, Vulnerabilities, and Mitigation Requirements).
- **Vulnerability & Mitigation XAI**: Implements dynamic prompt construction and async analysis for both vulnerabilities and mitigation controls. Reports are parsed and rendered via a dedicated client-side markdown formatter that handles nested headers, bullet/ordered lists, horizontal rules, and bold styling.
- **Vulnerability Registry Fallbacks**: If a vulnerability has no description, it dynamically falls back to its parent threat's mitigation description.
- **Asset Mapping & Deduplication**: Configures deduplication logic during project load to resolve ID collisions. Risk Assessment tables dynamically inspect DFD edges (data flows) to map carried assets back to components, falling back to elements' `asset_type` or "System Data".
- **AI Providers**: Pluggable interfaces for Google Gemini and Ollama.
- **Prompt Builder**: Dynamically builds multi-shot, instructional prompts.
- **Response Parser**: Resilient parser with partial-JSON recovery logic.

### 5. Security & Data
- **Project Files**: Projects are stored as structured JSON files, separating threats, vulnerabilities, mitigations, and design layouts.
- **Project Design Image**: Integrates `architecture.jpg` stored directly in the project directory, captured dynamically from the workspace.
- **Credential Storage**: API keys encrypted using Fernet (AES-128-CBC) and stored in `config.env`.
- **Key Management**: Uses PBKDF2 for key derivation.
- **Centralized Infrastructure**: Unifies path logic in `utils/paths.py` and constants in `core/constants.py`.

---

## Technology Stack

| Component | Technology |
| :--- | :--- |
| **Language** | Python 3.11+ |
| **GUI Framework** | PySide6 (Qt 6) |
| **Data Validation** | Pydantic v2 |
| **AI Integration** | Custom HTTPX-based providers (Gemini, Ollama) |
| **Encryption** | Cryptography.io (Fernet, PBKDF2) |
| **Export Formats** | Excel (OpenPyXL), Markdown, Diagram Images |

---

## Core Workflows

### AI Analysis Pipeline
1. **Extraction**: `DFDConverter` scans the Diagram Canvas and converts visual nodes/edges into a textual DFD representation.
2. **Segmentation**: If the architecture is complex, `ThreatAnalyzer` splits it into logical clusters.
3. **Execution**: The `PromptBuilder` sends the system context and DFD data to the configured `AIProvider`.
4. **Normalization**: `ResponseParser` cleans the raw AI text and maps it to the `Threat` model.
5. **Sync**: The `MainWindow` updates the `Threat Register` and refreshes the UI.

### Project Persistence
- **State Serialization**: All project states are serialized into structured JSON.
- **Data Partitioning**: Uses a sidecar file strategy to prevent data bloat and ensure Git-friendly diffs. Core metadata resides in `project.json`, while technical data is stored in specialized sidecars.
- **Persistence Integrity**: `ProjectManager` ensures that manual overrides to AI-generated threats are preserved during re-analysis.

---

## Web Designer REST API Endpoints

The local visual designer interacts with the desktop application backend through the following local HTTP server routes (served on loopback address `127.0.0.1`):

### 1. Project Management
*   **`GET /api/project`**: Loads the active project. Merges and formats data from `project.json`, `architecture.json`, `threats.json`, `vulnerabilities.json`, and `mitigations.json` sidecar files into a unified JSON workspace.
*   **`POST /api/project`**: Saves current diagrams, components, boundaries, custom component types, threats, vulnerabilities, and mitigations back to the project files.
*   **`POST /api/project/autosave`**: Performs periodic background auto-saving to prevent loss of editing states.
*   **`POST /api/project/image`**: Accepts base64 encoded JPG data, decodes it, and saves it as `architecture.jpg` in the project directory.

### 2. AI Infrastructure & Orchestration
*   **`GET /api/project/prompt_config`**: Retrieves the active project's business context, risk preferences, and custom AI prompt instructions.
*   **`POST /api/project/prompt_config`**: Saves updates to the project's business context and prompt configuration.
*   **`GET /api/ai/config`**: Retrieves active AI configurations, model names, endpoints, and credentials status.
*   **`POST /api/ai/config`**: Updates and encrypts AI provider credentials and configurations (including caps like `max_tokens`).
*   **`POST /api/ai/analyze`**: Runs STRIDE/LINDDUN threat analysis against DFD components.
*   **`POST /api/ai/mitigations`**: Initiates a background Map-Reduce review to group, deduplicate, and compile security requirements.
*   **`POST /api/ai/reason`**: Triggers Explainable AI (XAI) deep-dives. Accepts a payload specifying `threat_id`, `vulnerability_id`, or `req_id` to generate targeted technical reports.

### 3. Exports
*   **`GET /api/export/checklist_excel`**: Renders and downloads a consolidated Excel workbook containing security mitigation checklists.

- **Delta Updates**: Optimized save operations maintain undo/redo consistency during heavy modeling sessions.
