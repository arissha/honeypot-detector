# Honeypot Detector (v1.0.0)

A modular ethical hacking tool designed to detect and fingerprint potential honeypots running on target systems. Developed as part of the Ethical Hacking course (IKB31603).

---

## ⚖️ Legal Disclaimer

> **WARNING:** This tool is designed strictly for authorized security auditing and defensive testing. Unauthorized scanning of systems or networks without explicit prior permission is illegal and subject to prosecution under the **Computer Crimes Act 1997**. The user assumes full responsibility for any actions performed using this software. Startup execution requires explicit user confirmation (Y/N) before scanning begins.

---

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arissha/honeypot-detector.git
   ```

---

## 🔄 Attack Lifecycle Mapping

The Honeypot Detector operates strictly as a **read-only detection and fingerprinting tool** and does not exploit target systems. Below is how the network fingerprinting workflow maps across the ethical hacking lifecycle:

1. **Reconnaissance:** Verifies that the target falls within the authorized testing scope (`127.0.0.1` / `localhost` by default) before any network packet is transmitted.
2. **Scanning & Enumeration:** Sequentially probes five representative TCP ports across distinct service domains:
   * **Port 22 (SSH)** & **Port 23 (Telnet):** Remote administration services.
   * **Port 80 (HTTP):** Web server headers and metadata.
   * **Port 445 (SMB):** Windows SMB protocol negotiation.
   * **Port 502 (Modbus TCP):** Industrial Control System (ICS / SCADA) device identification.
3. **Information Gathering:** Collects initial service greetings passively (`SSH`, `Telnet`) or sends minimal read-only protocol requests (`HTTP HEAD`, `SMB2 Negotiate`, `Modbus Function 0x2B/0x0E Read Device ID`) capped at `1024` bytes, while measuring separate TCP connection (`connect_time_ms`) and initial response (`response_time_ms`) timings.
4. **Analysis & Interpretation:**
   * **Honeypot Signatures:** Compares captured banners and hex payloads against documented indicators for **Cowrie**, **Kippo**, **Dionaea**, **Conpot**, and **T-Pot** (`strong`, `moderate`, and `weak` indicators).
   * **Port Behaviour Heuristics:** Detects suspicious patterns such as all five ports accepting connections simultaneously, industrial Modbus (`502`) exposed alongside Windows SMB (`445`), identical banners across different ports, or mismatched protocol responses.
   * **Response Timing Analysis:** Flags uniform response latencies across disparate services or large application delays following fast TCP handshakes.
5. **Reporting:** Packages all network observations, matched evidence, confidence ratings, and legitimate alternative explanations into a structured dictionary for the scoring and reporting engine.

---

## 📋 Rules of Engagement (RoE)

### 1. Authorized Scope
* **Default Scope:** `127.0.0.1` (`localhost`) and local virtual machines or Docker containers owned by the assessment team.
* **Approved Lab Targets:** Only explicitly authorized lab IP addresses or domains may be tested. Scanning external public hosts or unauthorized networks is strictly prohibited.

### 2. Time Windows
* Testing must occur only during scheduled **IKB31603 lab sessions** or explicitly approved assessment testing windows.

### 3. Permitted Actions
* Sequential TCP connection checks on ports `22, 23, 80, 445, 502`.
* Basic passive banner grabbing (`SSH`, `Telnet`).
* Minimal read-only protocol identification (`HTTP HEAD/GET`, `SMB2 Negotiate`, `Modbus Read Device ID 0x2B/0x0E`).
* Network response timing measurements and local honeypot signature matching.

### 4. Prohibited Actions
* Unauthorized scanning outside the approved scope.
* Brute-force login attempts or credential submission/collection.
* Vulnerability exploitation, malformed packet injection, or data modification.
* Denial-of-Service (DoS) flooding or parallel high-rate scanning.
* Accessing services, shares, or data beyond the read-only fingerprinting scope.

### 5. Emergency Stop (Kill Switch)
* Stop testing immediately when instructed or when an anomaly occurs.
* Press **`Ctrl+C`** or trigger the application kill switch (`stop_event` / `STOP_SCAN` file) to abort an active scan cleanly.
* Cancelled scans exit safely without automatically restarting.



## 🖥️ Host-Based Detection (host_scan.py)

In addition to network fingerprinting, the tool inspects the **local host** for honeypot indicators. It operates entirely **read-only** and never modifies the system. Findings are weighted and passed to the scoring engine.

**Checks performed:**

* **Virtualisation / container:** VM vendor strings (`/sys/class/dmi/id/`), the CPU `hypervisor` flag, known hypervisor MAC prefixes (e.g. `08:00:27` VirtualBox), and Docker signatures (`/.dockerenv`, `/proc/1/cgroup`).
* **Low-activity indicators:** very short uptime (< 1 hour), unusually few running processes (< 50), and no genuine human user accounts (UID ≥ 1000).
* **Direct honeypot traces:** default hostnames (e.g. Cowrie's `svr04`), known honeypot directories (`/opt/cowrie`, `/opt/dionaea`, etc.), and running honeypot processes.

Each check returns a result with a `suspicious` flag, supporting evidence, and a weight (5–25), reflecting how strongly it indicates a honeypot.
