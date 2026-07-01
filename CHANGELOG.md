# Changelog

All notable changes to the ThreatPilot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
