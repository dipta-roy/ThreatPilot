# Changelog

All notable changes to the ThreatPilot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-06-29

This major release introduces a complete overhaul of the threat modeling engine, incorporating multi-modal AI vision, explainable AI reasoning, map-reduce data processing, and highly interactive manual modeling controls to create a truly hybrid AI/Human workflow.

### Added
#### Core AI & Architecture Engine
- **AI Vision Analysis**: Completely replaced traditional computer vision (OpenCV) with state-of-the-art Multi-Modal AI (Qwen2.5-VL & Gemini 3.1-Flash-Lite) for flawless, zero-dependency detection of architectural diagrams, components, and trust boundaries.
- **Explainable AI (XAI)**: Introduced a deep technical reasoning engine that dynamically generates inline rationalizations (Attack Vectors, Root Causes, Verification Procedures) for any threat, vulnerability, or mitigation.
- **Map-Reduce Mitigation Processor**: Implemented a recursive background batching (Map-Reduce) algorithm to automatically review, deduplicate, and consolidate hundreds of raw mitigations into cohesive security requirements, bypassing LLM context limits.

#### Risk Assessment & Visuals
- **Live Risk Counters**: Architecture nodes now feature real-time, pulsing badges displaying active threat counts that dynamically sync with the threat ledger.
- **Dynamic DFD Asset Mapping**: Automatically inspects data flow edges to map carried assets directly into the Risk Assessment matrix.
- **Vulnerability Mitigation Fallbacks**: The engine now dynamically inherits and falls back to parent threat mitigations if vulnerability-specific controls are missing.

#### Manual Data Entry & UX
- **Manual Risk & Threat Modeling**: Introduced comprehensive interactive modals (`AddThreatModal`, `AddRiskModal`, `AddVulnerabilityModal`, `AddMitigationModal`) into the web workspace, empowering users to manually override or augment AI-generated threat data effortlessly.
- **Integrated CVSS v3.1 Calculator**: Embedded a real-time CVSS base score calculator directly within the new manual entry UI, automatically resolving vector strings and severity categories.
- **AI Token Controls**: Added a `max_tokens` configuration parameter to both the backend API and the frontend AI Provider Settings to help control LLM generation sizes and prevent resource exhaustion.
- **Dynamic Context Resolving**: The Risk Assessment matrix and manual modals now dynamically extract elements and assets directly from active design nodes to streamline manual entry.

### Changed
- **Architecture Diagram Export**: Removed unreliable local `html-to-image` screenshot captures in favor of a cleaner export strategy or external tooling.
- **Dependency Reduction**: Dropped heavy legacy OpenCV dependencies, reducing the application footprint by over 80% while dramatically improving component detection accuracy.

---

## [1.8.0] - 2026-06-27

### Added
- **Interactive Web Architecture Designer**: Integrated a new browser-based visual workspace using **React Flow**, **TypeScript**, and **Tailwind CSS** to model complex Data Flow Diagrams (DFDs) side-by-side with the PySide6 desktop client.
- **Bi-Directional Save Syncing**: Added a lightweight, multi-threaded local REST server (`designer_server.py`) using Python's standard library to serve visual assets and expose safe endpoints to load/save `architecture.json` in real-time.
- **Workspace Theme Support**: Added seamless switching between Light and Dark themes with customized high-contrast styles, specifically tuned for selected/unselected carried security assets, bidirectional flow toggles, and property configuration panels.
- **Inline DFD Export Panel**: Embedded live generation panels directly inside the web UI for **ASCII block diagrams** and **Mermaid flowchart code**.
- **Real-Time Validation Alerts**: Added an interactive web-based validation panel to catch structural design issues (disconnected nodes, empty boundaries, circular loops) instantly.
- **Automated Developer Build System**: Created a build script (`build_designer.bat`) to compile TypeScript and bundle frontend assets for local distributions.
- **Local Web Server Security**: Bound the background HTTP server strictly to `localhost` (`127.0.0.1`) and restricted API access only to the active desktop workspace directory.

### Changed
- **MSI Installer Packaging**: Modified `msi-builder.py` to bundle the compiled designer static assets into frozen builds.
- **Dynamic Path Resolution**: Refactored `paths.py` to identify dynamic asset environments across debug, source, and frozen cx_Freeze executions.

---

## [1.7.2] - 2026-05-14

### Added
- **MITRE ATT&CK Mapping**: Implemented automated extraction mapping of vulnerabilities to specific defensive techniques.
- **Privacy Threat Modeling**: Native LINDDUN support alongside classic STRIDE methodology.
- **Vulnerability Register**: Introduced a decoupled register tracking base vulnerability scores with CVSS v3.1 calculators.
- **FERNET API Key Storage**: Added PBKDF2-derived master key encryption using OS Credential Manager (`keyring`) or high-security session keys.
