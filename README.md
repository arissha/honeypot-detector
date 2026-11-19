# Honeypot Detector (v1.0.0)
 
A modular ethical hacking tool designed to detect and fingerprint potential honeypots running on target systems. Developed as part of the Ethical Hacking course (IKB31603).

---
## 📌 1. Project Overview
### 1.1 Description
Honeypot Detector is a Python-based security tool designed to identify potential honeypots through network-based and host-based indicators.

The tool analyses service banners, open ports, response behaviour and selected local system characteristics to estimate the likelihood that a target is operating as a honeypot.

The system generates a likelihood score, classification verdict and supporting evidence in terminal and report formats.

### Project Information

| Item | Description |
|---|---|
| Project Name | Honeypot Detector |
| Version | 1.0.0 |
| Programming Language | Python 3 |
| Platform | Linux / Kali Linux |
| Attack Category | Reconnaissance and Honeypot Detection |
| Purpose | Defensive security analysis and research |

---
## 🔄 2.Attack Category & Lifecycle Mapping
### 2.1 Attack Category
The Honeypot Detector operates strictly as a **read-only detection and fingerprinting tool** and does not exploit target systems. Below is how the network fingerprinting workflow maps across the ethical hacking lifecycle:

### 2.2 Security Lifecycle Mapping
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
## 🏗️ 3. System Architecture

The Honeypot Detector uses a modular architecture consisting of network scanning, host scanning, pipeline integration, scoring and reporting components.

### 3.1 System Workflow

1. The user starts the program and provides a scan target where supported.
2. The main program validates the target and scan scope.
3. The network scanning module collects network-based indicators.
4. The host scanning module checks selected local system indicators where applicable.
5. The pipeline integrates and processes the findings.
6. The scoring module calculates the honeypot likelihood.
7. The reporting module displays and saves the scan results.

### 3.2 Data Flow Diagram
<img width="526" height="710" alt="image" src="https://github.com/user-attachments/assets/c5f5da60-3b8d-4782-bc7a-e5d49526bcc5" />


---

## ⚙️ 4. Detection Modules
The system consists of several modules that work together to perform honeypot detection.

| Module | Main Function |
|---|---|
| `modules/network_scan.py` | Examines network services, ports, banners and response behaviour. |
| `modules/host_scan.py` | Checks selected local host and virtualisation indicators. |
| `modules/pipeline.py` | Integrates scanner results and prepares findings. |
| `modules/scoring.py` | Calculates honeypot likelihood and classification. |
| `modules/reporting.py` | Displays results and generates JSON and TXT reports. |

## 4.1Host-Based Detection (host_scan.py)

In addition to network fingerprinting, the tool inspects the **local host** for honeypot indicators. It operates entirely **read-only** and never modifies the system. Findings are weighted and passed to the scoring engine.

**Checks performed:**

* **Virtualisation / container:** VM vendor strings (`/sys/class/dmi/id/`), the CPU `hypervisor` flag, known hypervisor MAC prefixes (e.g. `08:00:27` VirtualBox), and Docker signatures (`/.dockerenv`, `/proc/1/cgroup`).
* **Low-activity indicators:** very short uptime (< 1 hour), unusually few running processes (< 50), and no genuine human user accounts (UID ≥ 1000).
* **Direct honeypot traces:** default hostnames (e.g. Cowrie's `svr04`), known honeypot directories (`/opt/cowrie`, `/opt/dionaea`, etc.), and running honeypot processes.

Each check returns a result with a `suspicious` flag, supporting evidence, and a weight (5–25), reflecting how strongly it indicates a honeypot.

### 4.2 Scoring and Classification

The scoring module uses a weighted Noisy-OR approach to combine triggered findings.

The likelihood score is calculated using:

S = 1 - PRODUCT(1 - w_i * c_i)

Where:

- `w_i` = Weight assigned to a finding.
- `c_i` = Confidence value.
- `n` = Number of findings.

The resulting score is converted into a percentage and classified into four verdict levels:

| Score | Classification |
|---|---|
| Below 25% | UNLIKELY a honeypot |
| 25%–49% | POSSIBLY a honeypot |
| 50%–74% | LIKELY a honeypot |
| 75%–100% | VERY LIKELY a honeypot |

### 4.3 Reporting and Output

The reporting module provides:

- Terminal-based scan results.
- Honeypot likelihood percentage.
- Classification verdict.
- Network and host category scores.
- Detection findings and explanations.
- Timestamped JSON and TXT reports.

Generated reports are stored in the `output/` directory.

---
## 💻 5. Installation & Requirements

### 5.1 Requirements

The following software is required:

- Kali Linux or another supported Linux environment.
- Python 3.
- Git.
- Docker (optional, for the Cowrie honeypot demonstration).

### 5.2 Clone the Repository

```bash
git clone https://github.com/arissha/honeypot-detector.git
cd honeypot-detector
```

### 5.3 Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 5.4 Install Dependencies

```bash
pip install -r requirements.txt
```

Alternatively, dependencies can be installed directly:

```bash
pip3 install -r requirements.txt
```

---
## 🚀 6. Usage Instructions
All commands should be executed from the project directory.

### 6.1 Run the Detector

To start a scan using the default configuration:

```bash
python3 run_all.py
```

The program performs the configured checks and displays the resulting likelihood score, verdict and supporting findings.

### 6.2 Dry-Run Mode

To preview the planned scanning activities without executing the checks:

```bash
python3 run_all.py --dry-run
```

Dry-run mode allows users to review the planned checks before running a scan.

### 6.3 Scope Validation

The tool includes a scope restriction mechanism to prevent unauthorised external scanning.

Example:

```bash
python3 run_all.py -t 8.8.8.8
```

An out-of-scope target should be rejected by the scope guard.

### 6.4 View Generated Reports

Scan reports are saved in the `output/` directory.

To view the generated files:

```bash
ls output/
```

To inspect a JSON report:

```bash
cat output/filename.json
```

Replace `filename.json` with the actual generated report filename.

### 6.5 Stop Scan

A stop file can be used to request scan cancellation:

```bash
touch stopme
python3 run_all.py --stop-file stopme
rm stopme
```

The pipeline checks the stop-file condition and can stop the scan early.

### 6.7 Dry-run output showing planned checks
<img width="635" height="299" alt="image" src="https://github.com/user-attachments/assets/3c050a9a-c39e-4b43-9f3c-2203a9ede8c7" />

---
## 📸 7. Demonstration & Screenshots

The following screenshots demonstrate the tool's main functions.

### 7.1 Terminal output showing the detection result
<img width="553" height="351" alt="image" src="https://github.com/user-attachments/assets/43f0f58b-f407-4805-9b72-66135bdf0686" />

### 7.2 Generated JSON report
<img width="564" height="364" alt="image" src="https://github.com/user-attachments/assets/e0bfb1cf-cd28-4973-aea4-226c0a076714" />

### 7.3 Sample or Baseine Scan Report

<img width="635" height="313" alt="image" src="https://github.com/user-attachments/assets/36222240-4b50-4aec-8eca-b72b774bca34" />

### 7.4 First Cowrie Detection Scan
<img width="635" height="55" alt="image" src="https://github.com/user-attachments/assets/c36f919a-3da3-4cef-b842-f8f7c8ed748b" />

### 7.5 Second Cowrie Detection Scan
<img width="635" height="400" alt="image" src="https://github.com/user-attachments/assets/7ccb9005-e84d-405f-ab63-9bd46c66785e" />

---

## 🧪 8. Testing & Validation

The project includes automated tests to verify the scoring, reporting, pipeline integration, evidence sanitisation and scan safety features.

### 8.1 Run Automated Tests

Execute the following command:

```bash
python3 -m unittest test_scoring test_pipeline
```

**Verified test result: 26 tests passed.**

The tests cover:

- Scoring calculations and verdict classification.
- Confidence values and category scores.
- Report generation and safe filenames.
- Network and host detection integration.
- Evidence sanitisation.
- Dry-run safety.
- Stop-file cancellation.
- Remote target host-check restrictions.

### 8.2 Cowrie Testing

The project supports testing against Cowrie in an authorised local laboratory.

Cowrie can be deployed using Docker with SSH and Telnet ports mapped to the local machine.

Example:

```bash
sudo docker run -d \
  -p 22:2222 \
  -p 23:2223 \
  -e COWRIE_TELNET_ENABLED=yes \
  cowrie/cowrie
```

Check the running container:

```bash
sudo docker ps
```

Run the detector:

```bash
python3 run_all.py
```

The scan results can be examined for Cowrie-related SSH and Telnet signatures.

The automated Cowrie-like integration tests use simulated services. These are separate from the live Cowrie Docker demonstration.

### 8.3 Unit test output showing 26 tests passed
<img width="635" height="88" alt="image" src="https://github.com/user-attachments/assets/29765eee-2034-4891-8e88-a65efb90f294" />

---
## 🛡️ 9. Ethical Considerations

The Honeypot Detector is developed for educational, research and authorised defensive security purposes.

The following principles guide its use:

### Authorisation
Scanning must only be performed on systems for which permission has been granted.

### Scope Restriction
The scope guard helps prevent scans against unauthorised external targets.

### Non-Destructive Testing
The tool is designed to observe service responses and selected host indicators rather than modify or damage target systems.

### Data Protection
Generated reports are stored locally. Host evidence is sanitised by the pipeline where applicable.

### Transparency
Detection findings include explanations to help users understand the results.

---
## 📋 10. Rules of Engagement (RoE)

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

---

## 🤝 11. Responsible Disclosure

If testing identifies a potential security weakness or unexpected exposure:

1. Record the relevant findings and supporting evidence.
2. Avoid accessing, modifying or disclosing unrelated information.
3. Notify the system owner or authorised security contact privately.
4. Provide sufficient technical details to help verify the finding.
5. Allow the responsible organisation reasonable time to investigate and address the issue.
6. Do not publish sensitive information without permission.

---
##⚠️ 12. Limitations

The Honeypot Detector uses heuristic indicators and does not guarantee accurate identification of every honeypot.

Known limitations include:

- **False Positives:** Legitimate systems may exhibit characteristics commonly associated with honeypots.
- **Virtual Machines:** Virtualisation indicators may increase the likelihood score even when the target is not a honeypot.
- **Short Uptime:** Recently restarted systems may trigger uptime-related indicators.
- **Limited Signatures:** Unknown or customised honeypots may not match existing detection signatures.
- **Host-Based Checks:** Host checks are limited to applicable local targets and are not performed on remote systems.
- **Heuristic Scoring:** The likelihood percentage is an estimate, not a statistically validated probability.

Results should be interpreted alongside supporting evidence and verified through further authorised investigation.

---
## ⚖️13. Legal Disclaimer

> **WARNING:** This tool is designed strictly for authorized security auditing and defensive testing. Unauthorized scanning of systems or networks without explicit prior permission is illegal and subject to prosecution under the **Computer Crimes Act 1997**. The user assumes full responsibility for any actions performed using this software. Startup execution requires explicit user confirmation (Y/N) before scanning begins.

---

