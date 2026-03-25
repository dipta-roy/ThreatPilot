# Security Policy

## Supported Versions

ThreatPilot is a **desktop application** (PySide6 + Python). Only the latest release on the `main` branch is actively supported.

| Version | Supported          | Notes |
|---------|--------------------|-------|
| Latest (`main`) |  Yes | Actively maintained |

## Reporting a Vulnerability

**Please report security issues responsibly.**

- **Preferred**: Open a **private** security advisory on GitHub:  
  [https://github.com/dipta-roy/ThreatPilot/security/advisories/new](https://github.com/dipta-roy/ThreatPilot/security/advisories/new)

Include as much detail as possible:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix or mitigation

**Do not** report security issues via public issues or pull requests.

## Security Features

ThreatPilot was designed with security in mind from the start:

- **Credential Management**  
  API keys (OpenAI, Gemini, Claude, etc.) are **never stored in plaintext**.  
  - Master encryption key is generated with `Fernet.generate_key()` and stored in the OS credential manager (`keyring`).  
  - Symmetric encryption uses `cryptography.fernet` (AES-128-CBC).  
  - Encrypted keys live in `config.env` (excluded from git).

- **Input Validation & Sandboxing**  
  - Diagram images: strict extension whitelist (`.png`, `.jpg`, `.jpeg`), UUID-prefixed filenames, copied into project-scoped `diagrams/` folder. No path traversal possible.  
  - All data models use **Pydantic v2** for strict validation.  
  - AI responses are parsed with robust JSON repair and bracket balancing.

- **AI Prompt Security**  
  - System prompt is dynamically built from a safe `PromptConfig` model.  
  - Output is strictly enforced as JSON with detailed schema.  
  - No user input can inject arbitrary instructions into the core threat-modeling logic.

- **Project Isolation**  
  Every project lives in its own folder. Sensitive files (`project.json`, `threats.json`, diagrams) are isolated and excluded from version control.

- **Export Safety**  
  Excel exports sanitize formulas (`=`, `+`, `-`, `@` prefixed) to prevent formula injection.

- **Dependency Management**  
  All dependencies are **strictly pinned** in `requirements.txt`. Regular updates are performed to address upstream vulnerabilities.

## Dependency Updates & Supply-Chain Security

- We use exact version pins (`==`) to prevent unexpected updates.
- `requirements.txt` is updated whenever new security patches are available.
- OpenCV, cryptography, PySide6, and other core libraries are actively maintained and pinned to known-safe versions.

## Known Limitations (Low Risk)

- As a desktop tool, large malicious diagrams could theoretically cause high CPU/memory usage (standard computer-vision risk). The app runs locally and under user control.
- LLM-based analysis inherits standard prompt-injection risks, but output parsing is hardened to mitigate malformed responses.
- No remote code execution, network listeners, or database is present.

## How to Run Securely

1. Use the provided `run_threatpilot.bat` (Windows) or create a clean virtual environment.
2. Never share your `config.env` or run the app on untrusted machines.
3. Keep your OS credential manager (Keychain / Windows Credential Manager) protected.
4. Update dependencies regularly: `pip install -r requirements.txt --upgrade`.

---

Thank you for helping keep ThreatPilot secure!  
