# 🛡️ RansomGuard

**RansomShield** is a lightweight and effective anti-ransomware tool designed to detect, alert, and mitigate ransomware activity in real time using a combination of:

- 🔒 **Blacklist-based hash detection**
- 🧬 **YARA rule scanning**
- 🪤 **Honeypot trap monitoring**

---

## 🚀 Features

- **Hash Blacklisting:** Detects known ransomware executables using a curated blacklist of malicious file hashes (MD5, SHA256, etc.).
- **YARA Integration:** Scans files using custom or community-provided YARA rules to catch suspicious behaviors or patterns.
- **Honeypot System:** Monitors decoy folders/files for unauthorized access or encryption attempts.
- **Real-Time Alerts:** Instantly notifies when ransomware-like behavior is detected.
- **Quarantine Support:** Automatically isolates detected malicious files to prevent further damage.

---

## 🛠️ How It Works

1. **Startup Scan:** On launch, RansomShield loads the hash blacklist and YARA rules.
2. **Honeypot Deployment:** A hidden or decoy directory is deployed and monitored for changes.
3. **Continuous Monitoring:** The tool runs in the background, monitoring:
   - File executions against the blacklist.
   - Real-time file changes via YARA rules.
   - Unauthorized access to honeypots.
4. **Response:** On detection:
   - Malicious processes can be terminated.
   - Files moved to quarantine.
   - Logs and alerts are generated for admins or users.

---

## 📁 Project Structure

RansomGuard/
├── blacklist/               # Directory for blacklisted files (hashes or executables)
├── honeypot/                # Honeypot folder for bait files to catch ransomware
├── machinelearning/         # Folder for machine learning models and scripts
├── protectmodule/           # Core protection logic (e.g., file scanning, hash checking)
├── ui/                      # User Interface components (e.g., CTk buttons, windows)
├── yaramodule/              # YARA rule-related files and scripts
├── blint.exe                # Malicious executable for testing (or part of detection)
├── hashes.txt               # List of known malicious hashes (for blacklist detection)
├── RansomPyShield.py        # Main script to launch and control the RansomShield
├── README.md                # Project documentation (this file)
├── Rule.zip                 # Compressed YARA rules (possibly for extraction)
└── sigcheck.exe             # Tool for signature checking (possibly for file integrity)

## 🖥️ Requirements

- Python 3.8+
- [`customtkinter`](https://github.com/TomSchimansky/CustomTkinter)


Install dependencies:

```bash
pip install -r requirements.txt

```bash
python main.py