# Honeypot Detector (v1.0.0)

A modular ethical hacking tool designed to detect and fingerprint potential honeypots running on target systems. Developed as part of the Ethical Hacking course (IKB31603).

---

## ⚖️ Legal Disclaimer

> **WARNING:** This tool is designed strictly for authorized security auditing and defensive testing. Unauthorized scanning of systems or networks without explicit prior permission is illegal and subject to prosecution under the **Computer Crimes Act 1997**. The user assumes full responsibility for any actions performed using this software. Startup execution requires explicit user confirmation (Y/N) before scanning begins.

---

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/arissha/honeypot-detector.git](https://github.com/arissha/honeypot-detector.git)
   cd honeypot-detector

Install dependencies: <br>

pip install -r requirements.txt
<br>
 Usage & CLI Options
Run the tool from your terminal using main.py. The tool will prompt you for explicit authorization before proceeding.

<br>  python main.py -t <target_ip> [options] , <br>
Available CLI Flags:
-t, --target: Target IP address or domain to scan (default: 127.0.0.1 / localhost)

--dry-run: Simulate the scanning process without sending active network requests or modifying files

-h, --help: Display the help message, usage instructions, and available options

<br>  
Basic scan targeting localhost (default safe scope):

Bash
python main.py  <br>

Scan a specific authorized target IP:

Bash <br>
python main.py -t 192.168.1.50 <br>
Execute in dry-run mode (safe simulation): <br>

Bash
python main.py -t 127.0.0.1 --dry-run
🛑 Scope & Safety Controls
Scope Enforcement: Default target is locked to 127.0.0.1 / localhost to prevent unintended external scans.

Kill Switch: Abort execution cleanly at any time by pressing Ctrl+C. The program traps keyboard interrupts and exits safely without leaving hanging processes.






