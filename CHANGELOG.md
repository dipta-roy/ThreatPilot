# Changelog

All notable changes to the ThreatPilot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
