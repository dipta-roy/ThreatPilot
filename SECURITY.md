# Security Policy

## Table of Contents
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Security Architecture](#security-architecture)
- [Supported Versions](#supported-versions)
- [Best Practices for Users](#best-practices-for-users)

---

## Reporting a Vulnerability

The ThreatPilot team takes the security of our application and its users seriously. If you discover a security vulnerability, we would appreciate it if you report it to us responsibly.

**Please do not open a public issue for security vulnerabilities.**

- **Preferred**: Open a **private** security advisory on GitHub:  
  [https://github.com/dipta-roy/ThreatPilot/security/advisories/new](https://github.com/dipta-roy/ThreatPilot/security/advisories/new)

Include as much detail as possible:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix or mitigation

---

## Security Architecture

ThreatPilot is designed with a "Security-First" mindset, particularly concerning the handling of sensitive architectural data and AI credentials.

### 1. API Key & Credential Protection
- **Encryption at Rest**: Sensitive API keys (e.g., Gemini) are never stored in plain text. They are encrypted using **AES-128 (Fernet)**.
- **PBKDF2 Key Derivation**: Master encryption keys are derived using PBKDF2 with 100,000 iterations and a cryptographically secure salt.
- **Key Management**:
    - By default, ThreatPilot uses the OS-native Credential Manager (via `keyring`) for machine-bound key storage.
    - For high-security environments, users can provide a `THREATPILOT_MASTER_KEY` environment variable for session-based encryption.

### 2. AI Interaction Security
- **Hallucination Mitigation**: The AI Threat Generation Engine enforces strict boundaries separating direct evidence-based findings from speculative assumptions, creating highly deterministic threat models that prevent spurious alerts based on generic missing controls.
- **Prompt Injection Defense**: All user-provided metadata, architectural descriptions, and custom prompts are sanitized (XML escaping and newline removal) before being embedded into AI system instructions.
- **SSRF Protection**: AI endpoint URLs (e.g., Ollama instances) are strictly validated for standard `http://` or `https://` schemes. The legacy `urllib` module has been replaced by `httpx` to strictly prevent local file inclusion via the `file://` scheme.
- **Resource Limits**: Configurable parameters (like `max_tokens`) exist for AI endpoints to cap response size, mitigating potential resource exhaustion (Denial of Wallet/Service) caused by runaway LLM generation.
- **Header-Based Authentication**: Gemini API keys are transmitted via the `x-goog-api-key` HTTP header, ensuring they are not exposed in URL logs or intermediate proxies.

### 3. Data Privacy & Consent
- **Local-First Analysis**: We strongly recommend using **Ollama** for local-only analysis of sensitive systems.

- **Mandatory Consent**: A "Data Privacy Acknowledgement" is triggered before any architectural data is sent to cloud-based AI providers (e.g., Google Gemini).
- **Log Redaction**: ThreatPilot automatically redacts identified API keys and secrets from application logs and error traces.

### 4. Local Web Server Security (Architecture Designer)
- **Path Traversal Protection (CWE-22)**: The local SPA router strictly applies cryptographic `.resolve()` logic to prevent `../` path traversal attacks escaping the core `dist/` web root.
- **Default Localhost Binding**: By default, the built-in HTTP server for the visual designer strictly binds to the loopback interface (`127.0.0.1`) only, preventing external devices or remote attackers on the same network from accessing or modifying the project's DFD architecture.
- **Network Sharing with PIN Authentication**: When sharing is explicitly enabled via the "Host Architecture Workspace" dialog, the server rebinds to `0.0.0.0`. Remote clients are immediately redirected to a `/auth` login page where they must enter a randomly generated 8-digit numeric PIN displayed only in the desktop application. Successful authentication issues a cryptographically unique session cookie (`threatpilot_session`) that is validated on all subsequent API requests. Local loopback connections (`127.0.0.1`, `::1`) bypass PIN authentication entirely.
- **Session Isolation**: Each sharing session generates a fresh PIN and clears all prior session tokens. Stopping sharing immediately invalidates all remote sessions and rebinds the server to localhost only.
- **REST Endpoint Isolation**: The `/api/project` and `/api/project/prompt_config` load and save endpoints only interact with the currently active workspace directory of the desktop application, preventing arbitrary file access or directory traversal.
- **Project Image Save Validation**: The `/api/project/image` screenshot endpoint strictly decodes base64-encoded JPG payloads and writes them solely to `architecture.jpg` in the project's root folder, preventing path traversal attacks and raw binary writes outside the workspace.

### 5. Export Security
- **Excel Formula Injection**: All Excel exports are sanitized to prevent CSV/Formula injection by escaping leading control characters (`=`, `+`, `-`, `@`).
- **Markdown Integrity**: Markdown exports are sanitized to prevent structural injection and ensure report fidelity.

---

## Supported Versions

Currently, security updates are provided for the latest stable release of ThreatPilot.

| Version | Supported |
| ------- | --------- |
| 3.x.x   | ✅ Yes    |
| < 3.0.0 | ❌ No     |

---

## Best Practices for Users
- **Use Local Models**: For highly sensitive architecture, always use a local Ollama instance.
- **Rotate Keys**: Regularly rotate your AI provider API keys.
- **Session Keys**: In shared environments, use the `THREATPILOT_MASTER_KEY` environment variable rather than relying on the machine-bound OS keyring.
