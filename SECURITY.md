# Security Policy

## Reporting a Vulnerability

The ThreatPilot team takes the security of our application and its users seriously. If you discover a security vulnerability, we would appreciate it if you report it to us responsibly.

**Please do not open a public issue for security vulnerabilities.**

**Please report security issues responsibly.**

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
- **Prompt Injection Defense**: All user-provided metadata, architectural descriptions, and custom prompts are sanitized (XML escaping and newline removal) before being embedded into AI system instructions.
- **SSRF Protection**: AI endpoint URLs are strictly validated to prevent Server-Side Request Forgery against internal metadata services (e.g., `169.254.169.254`) and private IP ranges.
- **Header-Based Authentication**: Gemini API keys are transmitted via the `x-goog-api-key` HTTP header, ensuring they are not exposed in URL logs or intermediate proxies.

### 3. Data Privacy & Consent
- **Local-First Analysis**: We strongly recommend using **Ollama** for local-only analysis of sensitive systems.
- **Mandatory Consent**: A "Data Privacy Acknowledgement" is triggered before any architectural data is sent to cloud-based AI providers (e.g., Google Gemini).
- **Log Redaction**: ThreatPilot automatically redacts identified API keys and secrets from application logs and error traces.

### 4. Export Security
- **Excel Formula Injection**: All Excel exports are sanitized to prevent CSV/Formula injection by escaping leading control characters (`=`, `+`, `-`, `@`).
- **Markdown Integrity**: Markdown exports are sanitized to prevent structural injection and ensure report fidelity.

---

## Supported Versions

Currently, security updates are provided for the latest stable release of ThreatPilot.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅ Yes    |
| <= 0.5  | ❌ No     |

---

## Best Practices for Users
- **Use Local Models**: For highly sensitive architecture, always use a local Ollama instance.
- **Rotate Keys**: Regularly rotate your AI provider API keys.
- **Session Keys**: In shared environments, use the `THREATPILOT_MASTER_KEY` environment variable rather than relying on the machine-bound OS keyring.
