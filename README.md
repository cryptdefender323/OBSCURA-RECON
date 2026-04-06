<p align="center">
  <img src="https://raw.githubusercontent.com/cryptdefender323/OBSCURA-RECON/main/Framework%20recon%20dengan%20efek%20neon.png"/>
</p>
⚠️ DISCLAIMER: This tool is only for ethical hacking, penetration testing, and bug bounty purposes on officially licensed systems. Unauthorized use is a violation of law.

About OBSCURA-RECON
OBSCURA-RECON is a Go-based web reconnaissance tool designed for automated and intelligent directory/path discovery. It combines several techniques:
🔍 Multi-round discovery — Performs layered scanning based on the results of previous rounds
🛡️ WAF Bypass — Supports multiple bypass levels to penetrate Web Application Firewalls
🧠 Smart wordlist generation — Generates a dynamic wordlist from detected technologies
🔬 Tech fingerprinting — Detects the technologies and frameworks used by targets
🐛 CVE lookup — Maps discovered technologies to known CVEs
📊 PDF Report — Automatically generates professional reports in PDF format

⚙️ System Requirements
Components
Minimum Version Go 1.21+ OS Linux / macOS / Windows Gobuster (optional, if used as a backend)

🚀 Installation
1. Clone Repository
bashgit clone https://github.com/cryptdefender323/OBSCURA-RECON.git
cd OBSCURA-RECON

2. Install Dependencies
go mod tidy

3. Build Binary
   For Linux/macOS, give execute permission:
5. chmod +x obscura-recon

6.  (Optional) Install to System PATH
     # Linux / macOS
sudo mv obscura-recon /usr/local/bin/
# Verification
obscura-recon --help
