# ThreatPilot Vulnerability Title Generator Utility

This is a standalone graphical utility designed to batch-generate and backfill missing or placeholder titles for vulnerabilities in legacy project databases using your existing ThreatPilot AI configuration.

---

## Features

- **Backward Compatibility:** Reads your legacy or newly generated `vulnerabilities.json` databases, parses all existing vulnerability entries, and saves them back atomically.
- **AI Integration:** Reuses the main ThreatPilot application's global AI configuration (Gemini or Ollama), automatically parsing encrypted API keys and endpoints.
- **High-Fidelity GUI:** Built with PySide6 and styled with a premium dark mode matching ThreatPilot's color system.
- **Smart Filtering:** Option to only target and process entries with generic titles (like "New Vulnerability") or missing fields, ensuring fast processing.
- **Background Execution:** Generates titles in a background worker thread (`QThread`) with a responsive UI log and progress tracking.

---

## How to Run

1. Ensure the Python environment you use for ThreatPilot is active (containing PySide6, httpx, and dotenv).
2. Run the utility from the terminal inside the project root:
   ```bash
   python vuln-title-generator-utility/main.py
   ```
3. Click **Browse...** to select your project's `vulnerabilities.json` file.
4. Click **Load Database** to view the vulnerability list.
5. Check/uncheck entries you want to process, then click **Generate Titles**.
6. When completed, click **Save Changes** to commit updates atomically.

---

## Safe Removal

This utility is completely decoupled from the primary application. If you decide to delete the `vuln-title-generator-utility` folder, it **will not affect** or break ThreatPilot.
