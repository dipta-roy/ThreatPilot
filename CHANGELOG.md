# Changelog

All notable changes to the ThreatPilot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Removed
- **RAG Knowledge Base**: Completely removed the ChromaDB and sentence-transformers based Knowledge Base feature to reduce application overhead, package size, and build complexity.

## [3.0.0] - 2026-07-14

This major release completely overhauls the AI threat generation engine to eliminate hallucinations, enforce strict traceability, and align with true attacker-centric threat modeling.

### Added
- **Multi-Agent System Pipeline**: Replaced the monolithic LLM architecture with a modular assembly line (Traversal, Threat, Mitigation, Evidence, Compliance, and Reporting agents) to keep prompts hyper-focused and reduce hallucinations.
- **Context Propagation & Tri-Graph Architecture**: The engine now actively mutates a stateful `ThreatContext` object as it traverses the data flow graph, evaluating threats based on cumulative attack neighborhood contexts instead of isolated components.
- **AttackMemory Event Log**: Introduced chronological event logging that remembers previous attacker actions across trust boundaries, enabling sophisticated Kill-Chain reasoning.
- **Dynamic Knowledge Service**: Integrated a dynamic RAG (Retrieval-Augmented Generation) layer that injects precise compliance policies (e.g., NIST, HIPAA) exactly when relevant to the local traversal context.
- **ChromaDB Vector Store**: Upgraded the RAG Knowledge Base from simple keyword matching to a persistent ChromaDB vector database.
- **Offline Semantic Search**: Integrated the `BAAI/bge-base-en-v1.5` sentence transformer for true semantic understanding of architectural elements and compliance policies.
- **Knowledge Base Manager UI**: Added a new user interface dialog under Intelligence -> Manage Knowledge Base for end-users to add, edit, and delete their own corporate standards.
- **Offline Embedding Models**: End-users can now load pre-downloaded offline embedding models directly from the Knowledge Base UI, keeping the application entirely air-gapped without relying on HuggingFace downloads.
- **ThreatSession Reproducibility**: Implemented strict session tracking capturing the exact architectural snapshot, LLM version, and agent prompts used during generation.
- **Traceability & Auditing**: Threats now include an `evidence_traversal_path` and `source_dfd_node` linking them directly back to the exact architectural components and boundaries in the DFD.
- **Confidence Scores**: AI-generated findings now feature a `confidence` rating (High, Medium, Low) to help prioritize remediation efforts.
- **Vulnerability Categorization**: Introduced `weakness_type` to Vulnerabilities for structured categorization (e.g., Design weakness, Configuration weakness).
- **Assumption vs. Evidence Separation**: The engine now explicitly differentiates between findings supported by direct evidence in the architecture diagram and speculative assumptions (e.g., missing controls).
- **Knowledge Base Reset**: Added a "Clean All" feature and confirmation dialog in the Knowledge Base Manager UI to allow users to completely clear all vector records.
- **PyTorch Support**: Added PyTorch dependency for advanced local AI processing capabilities.
- **Type Hinting**: Resolved `NameError` for `Asset` class in DFD conversion logic (`dfd_converter.py`).

### Changed
- **Neighborhood Analysis Model**: Shifted the generation strategy to smaller, localized graph batches, solving "lost-in-the-middle" context degradation and significantly speeding up Time-To-First-Token (TTFT) for local LLMs.
- **Data-Driven Severity Escalation**: Added native logic for escalating base risk scores deterministically based on propagated data classification tags (e.g., PII, PHI, Credentials).
- **Attacker-Centric Titles**: Threat titles have been shifted from mitigation-centric labels ("Missing Rate Limiting") to true attacker behavior models ("API Resource Exhaustion") following strict STRIDE methodology.
- **Canonical Threats Engine**: Implemented robust prompt safeguards to deduplicate variants of the same threat into single, canonical threat profiles.
- **MITRE ATT&CK Mapping**: Enforced generation of specific, deterministic MITRE ATT&CK techniques based on the exact attack pattern.

### Fixed
- **Concurrency File Locking**: Fixed `[WinError 5] Access is denied` crashes caused by race conditions between background UI metadata polling and atomic `project.json` overwrites by implementing a resilient read-retry loop.
- **Contextual AI Narrative**: Fixed an issue where isolated, single-node AI analysis segments lost overall system data-flow context by deterministically injecting a global architecture narrative into all prompts.
- **MSI Installer Dependencies**: Fixed missing module errors in the frozen Windows executable by explicitly forcing `cx_Freeze` to bundle `torch`, `pypdf`, and `docx`.
- **Canvas UI Polish**: Hid the React Flow attribution watermark in the Web Designer for a cleaner, distraction-free modeling workspace.

---

## [2.2.0] - 2026-07-02

This release introduces dynamic workspace port configuration.

### Added
- **Configurable Workspace Port**: Added a "Workspace Settings" dialog under the Intelligence menu. Users can now easily configure the local and shared workspace server port instead of being restricted to port 8080.
- **Port Backward Compatibility**: Smoothly handles older configuration files by safely defaulting to 8080 when the setting is not present.

### Fixed
- **Authentication Resilience**: Fixed an issue where authentication failed if stale session cookies from different ports but the same IP were present. The server now intelligently scans all provided session cookies.
- **Sharing Details**: Re-wired the architecture workspace and sharing dialogs to dynamically reflect the newly configured port instead of hardcoded defaults.

## [2.1.0] - 2026-07-01

This release brings significant enhancements to Workspace Sharing security, auditability features for risk assessments, and quality-of-life improvements to the UI.

### Added
- **Workspace Sharing Security Overhaul**: 
  - Upgraded authentication from 6-digit to an **8-digit PIN** to better protect against brute force attacks on local networks.
  - Introduced optional **TLS (HTTPS)** encryption directly from the Sharing Dialog using dynamically generated self-signed certificates.
  - Enforced `HttpOnly`, `SameSite=Strict`, and `Secure` attributes on session cookies to prevent XSS-based cookie theft.
  - Implemented **Instant Access Revocation**: The React frontend now actively monitors connection state. If sharing is stopped (or restarted), the browser instantly detects `401 Unauthorized` responses or network failures and forcefully reloads, securely wiping sensitive architectural data from memory.
- **CVSS Modification Rationale**: Added a dedicated `cvss_rationale` field to Threat and Vulnerability models. Users must now supply a free-text justification when manually overriding AI-suggested CVSS vectors to maintain strong audit trails. This field is fully integrated into both the Desktop App (`properties_panel.py`, `threat_edit_dialog.py`, `cvss_dialog.py`) and the Web Designer modals.
- **Postman Collection**: Created an official `ThreatPilot.postman_collection.json` containing exhaustive documentation and examples for all REST APIs to streamline developer onboarding.
- **Click-to-Copy Connectivity Details**: The PIN and Network URL fields in the Designer Sharing Dialog are now fully clickable, automatically copying their values to the clipboard with visual "Copied!" feedback.

### Changed
- **Web Workspace Theme**: Switched the default theme of the Web Designer to Light Mode based on user feedback.
- **Terminology Update**: Migrated UI labels from "SSL" to "TLS" to accurately reflect the underlying protocol versions used (TLS 1.2/1.3).

## [2.0.0] - 2026-06-29

This major release introduces a complete overhaul of the threat modeling engine, incorporating multi-modal AI vision, explainable AI reasoning, map-reduce data processing, and highly interactive manual modeling controls to create a truly hybrid AI/Human workflow.

### Added
#### Core AI & Architecture Engine
- **Map-Reduce Mitigation Processor**: Implemented a recursive background batching (Map-Reduce) algorithm to automatically review, deduplicate, and consolidate hundreds of raw mitigations into cohesive security requirements, bypassing LLM context limits.

#### Risk Assessment & Visuals
- **Live Risk Counters in workspace**: Architecture nodes now feature real-time, pulsing badges displaying active threat counts that dynamically sync with the threat ledger.

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
