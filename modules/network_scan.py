"""
Network Fingerprinting Module (modules/network_scan.py)
OS-Specific Attack: Honeypot Detector (IKB31603 Ethical Hacking)

Provides Object-Oriented classes for:
1. Safe TCP Banner Grabbing on ports 22 (SSH), 23 (Telnet), 80 (HTTP), 445 (SMB), 502 (Modbus)
2. Honeypot Signature Matching (Cowrie, Kippo, Dionaea, Conpot, T-Pot)
3. Cross-Port Behaviour Heuristic Analysis
4. Network Response Timing Analysis
5. Sequential Rate-Limited Scanning with Emergency Kill-Switch & Dry-Run Support
"""

import argparse
import json
import os
import re
import socket
import time

# Default TCP ports monitored by the network fingerprinting module
DEFAULT_PORTS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    445: "SMB",
    502: "Modbus",
}

# Limit socket reads to 1024 bytes to prevent memory exhaustion
MAX_READ_BYTES = 1024

# Read-only SMB2 Negotiate request wrapped in a 4-byte NetBIOS header (checks dialect 0x0202 only)
SMB2_NEGOTIATE_PROBE = bytes.fromhex(
    "00000066"
    "fe534d42400000000000000000000100"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "240001000100000000000000"
    "00000000000000000000000000000000"
    "0000000000000000"
    "0202"
)

# Read-only Modbus TCP "Read Device Identification" request (Function 0x2B, MEI 0x0E)
MODBUS_DEVICE_ID_PROBE = bytes.fromhex("000100000005012b0e0100")

# Documented honeypot signature database for Cowrie, Kippo, Dionaea, Conpot, and T-Pot
DEFAULT_SIGNATURES = [
    {
        "id": "COWRIE-SSH-01",
        "honeypot": "Cowrie",
        "port": 22,
        "service": "SSH",
        "match_type": "contains",
        "pattern": "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
        "strength": "moderate",
        "description": "Legacy default SSH version banner shipped in cowrie.cfg.dist (inherited from Kippo).",
        "legitimate_note": "Could also appear on an unpatched Debian 7 server; banner alone is not conclusive proof.",
        "reference": "https://github.com/cowrie/cowrie/blob/main/etc/cowrie.cfg.dist",
    },
    {
        "id": "COWRIE-SSH-02",
        "honeypot": "Cowrie",
        "port": 22,
        "service": "SSH",
        "match_type": "contains",
        "pattern": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
        "strength": "weak",
        "description": "Default SSH version string used in newer Cowrie configuration templates.",
        "legitimate_note": "Standard banner for real Debian 10 OpenSSH servers; weak indicator on its own.",
        "reference": "https://github.com/cowrie/cowrie/blob/main/etc/cowrie.cfg.dist",
    },
    {
        "id": "COWRIE-TELNET-01",
        "honeypot": "Cowrie",
        "port": 23,
        "service": "Telnet",
        "match_type": "regex",
        "pattern": r"(Debian GNU/Linux 7.*svr04|svr04 login:)",
        "strength": "strong",
        "description": "Default hostname 'svr04' and Debian 7 Telnet prompt configured in Cowrie.",
        "legitimate_note": "Unlikely on production systems unless a host is genuinely named 'svr04'.",
        "reference": "https://github.com/cowrie/cowrie/blob/main/etc/cowrie.cfg.dist",
    },
    {
        "id": "KIPPO-SSH-01",
        "honeypot": "Kippo",
        "port": 22,
        "service": "SSH",
        "match_type": "contains",
        "pattern": "SSH-2.0-OpenSSH_5.1p1 Debian-5",
        "strength": "moderate",
        "description": "Classic default SSH version banner used by Kippo (predecessor to Cowrie).",
        "legitimate_note": "May rarely appear on obsolete Debian 5 legacy machines.",
        "reference": "https://github.com/desaster/kippo/blob/master/kippo.cfg.dist",
    },
    {
        "id": "KIPPO-SSH-02",
        "honeypot": "Kippo",
        "port": 22,
        "service": "SSH",
        "match_type": "contains",
        "pattern": "SSH-2.0-OpenSSH_5.5p1 Debian-6",
        "strength": "moderate",
        "description": "Documented Kippo SSH banner configuration mimicking Debian 6.",
        "legitimate_note": "Could exist on legacy Debian 6 systems; requires corroborating evidence.",
        "reference": "https://github.com/desaster/kippo",
    },
    {
        "id": "DIONAEA-SMB-01",
        "honeypot": "Dionaea",
        "port": 445,
        "service": "SMB",
        "match_type": "regex",
        "pattern": r"(HOMEUSER-3AF6FE|484f4d45555345522d334146364645)",
        "strength": "strong",
        "description": "Hardcoded default SMB ServerName 'HOMEUSER-3AF6FE' in Dionaea's smbfields.py.",
        "legitimate_note": "Highly specific to uncustomized Dionaea SMB emulation.",
        "reference": "https://github.com/DinoTools/dionaea/blob/master/modules/python/dionaea/smb/include/smbfields.py",
    },
    {
        "id": "DIONAEA-HTTP-01",
        "honeypot": "Dionaea",
        "port": 80,
        "service": "HTTP",
        "match_type": "regex",
        "pattern": r"Server:\s*nginx/1\.19\.2|Dionaea",
        "strength": "weak",
        "description": "HTTP server header pattern commonly used in default Dionaea / T-Pot HTTP profiles.",
        "legitimate_note": "Real nginx web servers may use the same version string; weak indicator on its own.",
        "reference": "https://dionaea.readthedocs.io/",
    },
    {
        "id": "CONPOT-MODBUS-01",
        "honeypot": "Conpot",
        "port": 502,
        "service": "Modbus",
        "match_type": "regex",
        "pattern": r"MODBUS_MEI_RESPONSE.*Siemens.*SIMATIC.*S7-200",
        "strength": "strong",
        "description": "Default Conpot Modbus template returning VendorName='Siemens', ProductCode='SIMATIC', Revision='S7-200'.",
        "legitimate_note": "Real Siemens S7-200 PLCs rarely expose this exact default XML string alongside IT services.",
        "reference": "https://github.com/mushorg/conpot/blob/master/conpot/templates/default/modbus/modbus.xml",
    },
    {
        "id": "CONPOT-MODBUS-02",
        "honeypot": "Conpot",
        "port": 502,
        "service": "Modbus",
        "match_type": "regex",
        "pattern": r"MODBUS_MEI_RESPONSE.*(Siemens|SIMATIC|Technodrome)",
        "strength": "moderate",
        "description": "Partial match for Conpot's default Siemens SIMATIC or 'Technodrome' ICS device strings.",
        "legitimate_note": "Verify whether the target is an authorized industrial PLC before assuming Conpot.",
        "reference": "https://github.com/mushorg/conpot/blob/master/conpot/templates/default/template.xml",
    },
    {
        "id": "CONPOT-HTTP-01",
        "honeypot": "Conpot",
        "port": 80,
        "service": "HTTP",
        "match_type": "regex",
        "pattern": r"(Last-Modified:\s*Tue,\s*19\s*May\s*1993|Technodrome)",
        "strength": "strong",
        "description": "Default Conpot HTTP SCADA web template containing hardcoded 19 May 1993 Last-Modified header.",
        "legitimate_note": "The 19 May 1993 timestamp is hardcoded in Conpot's default http.xml template.",
        "reference": "https://github.com/mushorg/conpot/blob/master/conpot/templates/default/http/http.xml",
    },
    {
        "id": "TPOT-HTTP-01",
        "honeypot": "T-Pot",
        "port": 80,
        "service": "HTTP",
        "match_type": "regex",
        "pattern": r"(T-Pot|tpotce|dtag-dev-sec)",
        "strength": "moderate",
        "description": "Banner or HTTP response referencing the T-Pot multi-honeypot platform.",
        "legitimate_note": "T-Pot runs Cowrie, Dionaea, and Conpot containers simultaneously on one host.",
        "reference": "https://github.com/telekom-security/tpotce",
    },
]


class PortScanResult:
    """Stores the scan observation data for a single TCP port."""

    def __init__(self, target, port, service):
        self.target = target
        self.port = port
        self.service = service
        self.state = "closed"
        self.banner = ""
        self.raw_hex = ""
        self.connect_time_ms = None
        self.response_time_ms = None
        self.probe_used = "passive"
        self.matched_signatures = []
        self.error = None

    def to_dict(self):
        """Convert the port result into a dictionary for JSON reports and scoring."""
        return {
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "banner": self.banner,
            "raw_hex": self.raw_hex,
            "connect_time_ms": self.connect_time_ms,
            "response_time_ms": self.response_time_ms,
            "probe_used": self.probe_used,
            "matched_signatures": [sig.to_dict() for sig in self.matched_signatures],
            "error": self.error,
        }


class BannerGrabber:
    """Connects to TCP ports and safely collects read-only service banners."""

    def __init__(
        self,
        connect_timeout=3.0,
        read_timeout=3.0,
        max_bytes=MAX_READ_BYTES,
        socket_factory=None,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_bytes = max_bytes
        self.socket_factory = socket_factory

    def _create_socket(self):
        """Create a standard TCP socket (or a test socket when running unit tests)."""
        if self.socket_factory is not None:
            return self.socket_factory()
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _receive_limited(self, sock):
        """Read up to max_bytes from the socket and measure response latency in ms."""
        start_read = time.perf_counter()
        data = sock.recv(self.max_bytes)
        elapsed_ms = round((time.perf_counter() - start_read) * 1000.0, 2)
        return data, elapsed_ms

    def build_http_probe(self, target, method="HEAD"):
        """Build a minimal HTTP/1.0 request that closes the connection immediately."""
        request_text = (
            f"{method} / HTTP/1.0\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: HoneypotDetector/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        return request_text.encode("ascii", errors="ignore")

    def format_banner_output(self, service, raw_bytes):
        """Convert raw protocol bytes into a readable banner string."""
        if not raw_bytes:
            return ""

        # Check for SMB2 (\xfeSMB) or SMB1 (\xffSMB) protocol headers
        if service == "SMB":
            printable = "".join(chr(b) if 32 <= b <= 126 else " " for b in raw_bytes)
            clean_text = " ".join(printable.split())
            if b"\xfeSMB" in raw_bytes:
                return f"SMB2_NEGOTIATE_RESPONSE {clean_text}".strip()
            if b"\xffSMB" in raw_bytes:
                return f"SMB1_NEGOTIATE_RESPONSE {clean_text}".strip()

        # Extract vendor/product text from Modbus Function 0x2B responses
        if service == "Modbus":
            printable = "".join(chr(b) if 32 <= b <= 126 else " " for b in raw_bytes[7:])
            clean_text = " ".join(printable.split())
            if len(raw_bytes) >= 8 and raw_bytes[7] == 0x2B:
                return f"MODBUS_MEI_RESPONSE {clean_text}".strip()
            if len(raw_bytes) >= 8 and (raw_bytes[7] & 0x80):
                exc_code = raw_bytes[8] if len(raw_bytes) > 8 else 0
                return f"MODBUS_EXCEPTION_{exc_code:02X} {clean_text}".strip()

        # Strip 3-byte Telnet IAC negotiation commands (0xFF + cmd + option) to reveal login text
        if service == "Telnet" and b"\xff" in raw_bytes:
            chars = []
            i = 0
            while i < len(raw_bytes):
                if raw_bytes[i] == 0xFF and i + 2 < len(raw_bytes):
                    i += 3
                else:
                    b = raw_bytes[i]
                    if 32 <= b <= 126 or b in (10, 13, 9):
                        chars.append(chr(b))
                    i += 1
            text_part = "".join(chars).strip()
            return f"TELNET_IAC {text_part}" if text_part else "TELNET_IAC_ONLY"

        return raw_bytes.decode("utf-8", errors="replace").strip()

    def _probe_http(self, sock, target, port, result):
        """Send an HTTP HEAD request first, falling back to GET only if HEAD fails or returns 405."""
        result.probe_used = "HTTP_HEAD"
        raw_data = b""
        try:
            sock.sendall(self.build_http_probe(target, method="HEAD"))
            raw_data, resp_ms = self._receive_limited(sock)
            result.response_time_ms = resp_ms
        except socket.timeout:
            result.error = "HTTP HEAD request timed out waiting for response"

        if not raw_data or b"405 " in raw_data[:32]:
            try:
                sock.close()
            except OSError:
                pass

            fallback_sock = self._create_socket()
            fallback_sock.settimeout(self.connect_timeout)
            try:
                fallback_sock.connect((target, port))
                fallback_sock.settimeout(self.read_timeout)
                result.probe_used = "HTTP_GET_FALLBACK"
                fallback_sock.sendall(self.build_http_probe(target, method="GET"))
                raw_data, resp_ms = self._receive_limited(fallback_sock)
                result.response_time_ms = resp_ms
                result.error = None
            except socket.timeout:
                result.error = "HTTP GET fallback timed out waiting for response"
            except OSError as exc:
                result.error = f"HTTP GET fallback error: {exc}"
            finally:
                try:
                    fallback_sock.close()
                except OSError:
                    pass

        return raw_data

    def grab_banner(self, target, port, service_name=None):
        """Connect to a single TCP port, collect its banner, and record connection/response times."""
        service = service_name or DEFAULT_PORTS.get(port, f"Port-{port}")
        result = PortScanResult(target=target, port=port, service=service)

        sock = self._create_socket()
        sock.settimeout(self.connect_timeout)

        try:
            # Measure TCP 3-way handshake time
            start_connect = time.perf_counter()
            sock.connect((target, port))
            result.connect_time_ms = round((time.perf_counter() - start_connect) * 1000.0, 2)
            result.state = "open"

            # Measure initial service response time using the read timeout
            sock.settimeout(self.read_timeout)
            raw_data = b""

            if service in ("SSH", "Telnet"):
                result.probe_used = "passive_greeting"
                try:
                    raw_data, result.response_time_ms = self._receive_limited(sock)
                except socket.timeout:
                    result.error = "Open port did not send an initial greeting before timeout"

            elif service == "HTTP":
                raw_data = self._probe_http(sock, target, port, result)

            elif service == "SMB":
                result.probe_used = "SMB2_NEGOTIATE"
                try:
                    sock.sendall(SMB2_NEGOTIATE_PROBE)
                    raw_data, result.response_time_ms = self._receive_limited(sock)
                except socket.timeout:
                    result.error = "SMB negotiate probe timed out"

            elif service == "Modbus":
                result.probe_used = "MODBUS_READ_DEVICE_ID"
                try:
                    sock.sendall(MODBUS_DEVICE_ID_PROBE)
                    raw_data, result.response_time_ms = self._receive_limited(sock)
                except socket.timeout:
                    result.error = "Modbus device identification probe timed out"

            else:
                result.probe_used = "passive_only"
                try:
                    raw_data, result.response_time_ms = self._receive_limited(sock)
                except socket.timeout:
                    result.error = "No banner received within read timeout"

            if raw_data:
                result.raw_hex = raw_data.hex()
                result.banner = self.format_banner_output(service, raw_data)

        except socket.timeout:
            result.state = "timeout"
            result.error = f"Connection timed out after {self.connect_timeout}s"
        except ConnectionRefusedError:
            result.state = "closed"
            result.error = "Connection refused (port closed)"
        except OSError as exc:
            result.state = "error"
            result.error = str(exc)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        return result


class SignatureMatch:
    """Stores a single matched honeypot indicator, its strength, and matched evidence."""

    def __init__(
        self,
        signature_id,
        honeypot,
        port,
        service,
        strength,
        evidence,
        description,
        legitimate_note="",
        reference="",
    ):
        self.signature_id = signature_id
        self.honeypot = honeypot
        self.port = port
        self.service = service
        self.strength = strength
        self.evidence = evidence
        self.description = description
        self.legitimate_note = legitimate_note
        self.reference = reference

    def to_dict(self):
        """Convert the matched signature into a dictionary."""
        return {
            "signature_id": self.signature_id,
            "honeypot": self.honeypot,
            "port": self.port,
            "service": self.service,
            "strength": self.strength,
            "evidence": self.evidence,
            "description": self.description,
            "legitimate_note": self.legitimate_note,
            "reference": self.reference,
        }


class SignatureMatcher:
    """Evaluates port banners and raw hex responses against the honeypot signature database."""

    def __init__(self, db_path=None):
        self.db_path = db_path
        self.signatures = self.load_signatures(db_path)

    def load_signatures(self, filepath=None):
        """Load signature rules from a JSON file if provided, or use DEFAULT_SIGNATURES."""
        if filepath and os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as file_obj:
                return json.load(file_obj)
        return list(DEFAULT_SIGNATURES)

    def _match_single_rule(self, rule, combined_text):
        """Check if a rule's pattern matches the banner text using exact, contains, or regex."""
        pattern = rule.get("pattern", "")
        match_type = rule.get("match_type", "contains").lower()

        if not pattern or not combined_text:
            return None

        if match_type == "exact":
            if combined_text.strip().lower() == pattern.strip().lower():
                return combined_text.strip()

        elif match_type == "contains":
            idx = combined_text.lower().find(pattern.lower())
            if idx != -1:
                return combined_text[idx : idx + len(pattern)]

        elif match_type == "regex":
            hit = re.search(pattern, combined_text, flags=re.IGNORECASE | re.DOTALL)
            if hit:
                matched = hit.group(0).strip()
                return matched[:137] + "..." if len(matched) > 140 else matched

        return None

    def match_port(self, port_result):
        """Check a PortScanResult against all applicable rules in the signature database."""
        if not port_result.banner and not port_result.raw_hex:
            return []

        combined_text = f"{port_result.banner}\n{port_result.raw_hex}".strip()
        matches = []

        for rule in self.signatures:
            rule_port = rule.get("port")
            rule_service = rule.get("service", "")

            if rule_port != port_result.port and rule_service.lower() != port_result.service.lower():
                continue

            evidence = self._match_single_rule(rule, combined_text)
            if evidence is not None:
                matches.append(
                    SignatureMatch(
                        signature_id=rule.get("id", "UNKNOWN"),
                        honeypot=rule.get("honeypot", "Unknown"),
                        port=port_result.port,
                        service=port_result.service,
                        strength=rule.get("strength", "weak"),
                        evidence=evidence,
                        description=rule.get("description", ""),
                        legitimate_note=rule.get("legitimate_note", ""),
                        reference=rule.get("reference", ""),
                    )
                )

        port_result.matched_signatures = matches
        return matches

    def check_tpot_platform_correlation(self, port_results):
        """
        Detect T-Pot multi-honeypot deployments when 2 or more distinct honeypot
        families (Cowrie, Kippo, Dionaea, Conpot) are matched on the same host.
        """
        detected_families = set()
        evidence_parts = []

        for res in port_results:
            for sig in res.matched_signatures:
                if sig.honeypot in ("Cowrie", "Kippo", "Dionaea", "Conpot"):
                    detected_families.add(sig.honeypot)
                    evidence_parts.append(f"{sig.honeypot} on port {res.port}")

        if len(detected_families) >= 2:
            return SignatureMatch(
                signature_id="TPOT-MULTI-01",
                honeypot="T-Pot",
                port=0,
                service="Multi-Port",
                strength="strong",
                evidence=", ".join(sorted(set(evidence_parts))),
                description=(
                    "Multiple distinct honeypot daemon signatures detected on the same host, "
                    "matching the T-Pot multi-honeypot platform."
                ),
                legitimate_note=(
                    "A single production host rarely serves legacy Debian SSH, Dionaea SMB, "
                    "and Siemens S7-200 Modbus PLC services simultaneously."
                ),
                reference="https://github.com/telekom-security/tpotce",
            )

        return None


class BehaviourObservation:
    """Stores a behavioural heuristic observation, confidence level, and legitimate explanations."""

    def __init__(
        self,
        check_name,
        ports_involved,
        description,
        evidence,
        confidence,
        legitimate_reasons,
    ):
        self.check_name = check_name
        self.ports_involved = list(ports_involved)
        self.description = description
        self.evidence = evidence
        self.confidence = confidence
        self.legitimate_reasons = legitimate_reasons

    def to_dict(self):
        """Convert the observation into a dictionary."""
        return {
            "check_name": self.check_name,
            "ports_involved": self.ports_involved,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "legitimate_reasons": self.legitimate_reasons,
        }


class PortBehaviourAnalyzer:
    """Checks scanned ports for suspicious cross-port behaviour patterns."""

    def __init__(self, expected_port_count=5):
        self.expected_port_count = expected_port_count

    def analyze(self, port_results):
        """Run all behavioural checks across open ports and return a list of observations."""
        observations = []
        open_results = [r for r in port_results if r.state == "open"]
        if not open_results:
            return observations

        self._check_open_port_counts(open_results, observations)
        self._check_unusual_service_combinations(open_results, observations)
        self._check_identical_or_silent_responses(open_results, observations)
        self._check_protocol_mismatches(open_results, observations)
        self._check_repetitive_banners(open_results, observations)
        return observations

    def _check_open_port_counts(self, open_results, observations):
        """Flag when all 5 (or 4 out of 5) monitored ports accept connections simultaneously."""
        open_ports = [r.port for r in open_results]
        open_count = len(open_ports)

        if open_count >= self.expected_port_count and self.expected_port_count >= 5:
            observations.append(
                BehaviourObservation(
                    check_name="all_monitored_ports_open",
                    ports_involved=open_ports,
                    description="All 5 monitored ports (SSH, Telnet, HTTP, SMB, Modbus) are open simultaneously.",
                    evidence=f"Open ports: {open_ports}",
                    confidence="high",
                    legitimate_reasons="Could be a multi-service lab gateway, though rare on a single production host.",
                )
            )
        elif open_count == 4:
            observations.append(
                BehaviourObservation(
                    check_name="high_open_port_count",
                    ports_involved=open_ports,
                    description=f"4 out of {self.expected_port_count} monitored ports are open on the same host.",
                    evidence=f"Open ports: {open_ports}",
                    confidence="moderate",
                    legitimate_reasons="Could be a multipurpose internal server with several management interfaces enabled.",
                )
            )

    def _check_unusual_service_combinations(self, open_results, observations):
        """Flag conflicting service pairings such as industrial Modbus + Windows SMB."""
        open_services = {r.service: r.port for r in open_results}

        if "Modbus" in open_services and "SMB" in open_services:
            observations.append(
                BehaviourObservation(
                    check_name="unusual_service_combination_ics_smb",
                    ports_involved=[open_services["SMB"], open_services["Modbus"]],
                    description="Industrial Modbus TCP (port 502) is open alongside Windows SMB (port 445).",
                    evidence="Both SMB (445) and Modbus (502) accepted connections.",
                    confidence="moderate",
                    legitimate_reasons="A Windows SCADA engineering workstation could run an HMI alongside file sharing.",
                )
            )

        if "SSH" in open_services and "Telnet" in open_services:
            observations.append(
                BehaviourObservation(
                    check_name="ssh_and_telnet_both_enabled",
                    ports_involved=[open_services["SSH"], open_services["Telnet"]],
                    description="Both encrypted SSH (22) and cleartext Telnet (23) are enabled together.",
                    evidence="Ports 22 and 23 are both open.",
                    confidence="low",
                    legitimate_reasons="Legacy network equipment sometimes keeps Telnet enabled for backward compatibility.",
                )
            )

    def _check_identical_or_silent_responses(self, open_results, observations):
        """Flag different service ports that return the exact same banner or stay completely silent."""
        banner_to_ports = {}
        silent_ports = []

        for res in open_results:
            banner = res.banner.strip()
            if not banner:
                silent_ports.append(res.port)
            else:
                banner_to_ports.setdefault(banner, []).append(res.port)

        for banner_text, ports in banner_to_ports.items():
            if len(ports) >= 2:
                observations.append(
                    BehaviourObservation(
                        check_name="identical_cross_port_banners",
                        ports_involved=ports,
                        description="Multiple different ports returned the exact same service banner.",
                        evidence=f"Ports {ports} returned: '{banner_text[:60]}'",
                        confidence="high",
                        legitimate_reasons="A firewall warning banner or reverse proxy may intercept multiple ports.",
                    )
                )

        if len(silent_ports) >= 3:
            observations.append(
                BehaviourObservation(
                    check_name="multiple_silent_open_ports",
                    ports_involved=silent_ports,
                    description=f"{len(silent_ports)} open ports accepted connections but sent no banner.",
                    evidence=f"Silent open ports: {silent_ports}",
                    confidence="moderate",
                    legitimate_reasons="Stateful firewalls or services awaiting custom handshakes may stay silent.",
                )
            )

    def _check_protocol_mismatches(self, open_results, observations):
        """Flag ports whose banner does not match the expected protocol format."""
        for res in open_results:
            banner = res.banner.strip()
            if not banner:
                continue

            mismatch = None
            if res.service == "SSH" and not banner.startswith("SSH-"):
                mismatch = f"Expected 'SSH-' prefix, got '{banner[:50]}'"
            elif res.service == "HTTP" and "HTTP/" not in banner.upper() and "<HTML" not in banner.upper():
                mismatch = f"Expected HTTP header, got '{banner[:50]}'"
            elif res.service == "SMB" and not banner.startswith(("SMB1_NEGOTIATE_RESPONSE", "SMB2_NEGOTIATE_RESPONSE")):
                mismatch = f"Expected SMB negotiate header, got '{banner[:50]}'"
            elif res.service == "Modbus" and not banner.startswith(("MODBUS_MEI_RESPONSE", "MODBUS_EXCEPTION_")):
                mismatch = f"Expected Modbus response frame, got '{banner[:50]}'"

            if mismatch:
                observations.append(
                    BehaviourObservation(
                        check_name="mismatched_protocol_response",
                        ports_involved=[res.port],
                        description=f"Port {res.port} ({res.service}) returned a non-standard protocol response.",
                        evidence=mismatch,
                        confidence="moderate",
                        legitimate_reasons="An administrator may run a custom service on a non-standard port.",
                    )
                )

    def _check_repetitive_banners(self, open_results, observations):
        """Flag synthetic-looking banners dominated by a single repeated character."""
        for res in open_results:
            banner = res.banner.strip()
            if len(banner) >= 20:
                most_common_count = max(banner.count(ch) for ch in set(banner))
                if most_common_count / len(banner) >= 0.75:
                    observations.append(
                        BehaviourObservation(
                            check_name="repetitive_or_artificial_banner",
                            ports_involved=[res.port],
                            description=f"Port {res.port} returned a highly repetitive banner string.",
                            evidence=f"Repeated banner pattern: '{banner[:40]}...'",
                            confidence="moderate",
                            legitimate_reasons="Some MOTD login banners use long lines of dashes or asterisks.",
                        )
                    )


class TimingObservation:
    """Stores a network timing observation, millisecond evidence, and legitimate reasons."""

    def __init__(
        self,
        check_name,
        ports_involved,
        description,
        evidence,
        confidence,
        legitimate_reasons,
    ):
        self.check_name = check_name
        self.ports_involved = list(ports_involved)
        self.description = description
        self.evidence = evidence
        self.confidence = confidence
        self.legitimate_reasons = legitimate_reasons

    def to_dict(self):
        """Convert the timing observation into a dictionary."""
        return {
            "check_name": self.check_name,
            "ports_involved": self.ports_involved,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "legitimate_reasons": self.legitimate_reasons,
        }


class TimingAnalyzer:
    """Computes timing statistics and detects unusual response latency patterns."""

    def __init__(
        self,
        uniform_spread_threshold_ms=5.0,
        high_response_threshold_ms=200.0,
        response_to_connect_ratio=15.0,
    ):
        self.uniform_spread_threshold_ms = uniform_spread_threshold_ms
        self.high_response_threshold_ms = high_response_threshold_ms
        self.response_to_connect_ratio = response_to_connect_ratio

    def summarize_metrics(self, port_results):
        """Calculate average connection and response times across all checked ports."""
        connect_times = {}
        response_times = {}
        timed_out_ports = []

        for res in port_results:
            if res.connect_time_ms is not None:
                connect_times[res.port] = res.connect_time_ms
            if res.response_time_ms is not None:
                response_times[res.port] = res.response_time_ms
            err = (res.error or "").lower()
            if res.state == "timeout" or (res.state == "open" and "timeout" in err):
                timed_out_ports.append(res.port)

        avg_connect = (
            round(sum(connect_times.values()) / len(connect_times), 2)
            if connect_times
            else None
        )
        avg_response = (
            round(sum(response_times.values()) / len(response_times), 2)
            if response_times
            else None
        )

        return {
            "average_connect_ms": avg_connect,
            "average_response_ms": avg_response,
            "connect_times_ms": connect_times,
            "response_times_ms": response_times,
            "timed_out_ports": timed_out_ports,
        }

    def analyze(self, port_results):
        """Evaluate timing measurements and return a list of TimingObservation objects."""
        observations = []
        if not port_results:
            return observations

        self._check_uniform_response_times(port_results, observations)
        self._check_application_vs_handshake_delay(port_results, observations)
        self._check_read_timeouts_on_open_ports(port_results, observations)
        return observations

    def _check_uniform_response_times(self, port_results, observations):
        """Flag when 3+ distinct open services respond with nearly identical latency."""
        measured = [
            (r.port, r.response_time_ms)
            for r in port_results
            if r.state == "open" and r.response_time_ms is not None
        ]

        if len(measured) >= 3:
            times = [val for _, val in measured]
            spread = round(max(times) - min(times), 2)
            avg_val = sum(times) / len(times)

            if avg_val >= 10.0 and spread <= self.uniform_spread_threshold_ms:
                ports = [p for p, _ in measured]
                pairs = ", ".join(f"port {p}: {t}ms" for p, t in measured)
                observations.append(
                    TimingObservation(
                        check_name="uniform_cross_service_response_time",
                        ports_involved=ports,
                        description=f"Three or more services responded with nearly identical times (spread: {spread} ms).",
                        evidence=pairs,
                        confidence="moderate",
                        legitimate_reasons="Localhost testing or shared reverse proxies can produce similar latencies.",
                    )
                )

    def _check_application_vs_handshake_delay(self, port_results, observations):
        """Flag ports where the TCP handshake is fast but the banner response is much slower."""
        flagged_ports = []
        evidence_list = []

        for res in port_results:
            if res.state == "open" and res.connect_time_ms is not None and res.response_time_ms is not None:
                effective_connect = max(res.connect_time_ms, 0.5)
                if (
                    res.response_time_ms >= self.high_response_threshold_ms
                    and (res.response_time_ms / effective_connect) >= self.response_to_connect_ratio
                ):
                    flagged_ports.append(res.port)
                    evidence_list.append(
                        f"port {res.port} (connect={res.connect_time_ms}ms, response={res.response_time_ms}ms)"
                    )

        if flagged_ports:
            observations.append(
                TimingObservation(
                    check_name="high_application_response_delay",
                    ports_involved=flagged_ports,
                    description="TCP handshake finished quickly, but the initial service banner was delayed.",
                    evidence="; ".join(evidence_list),
                    confidence="low",
                    legitimate_reasons="Real SSH servers may perform reverse DNS checks before sending a banner.",
                )
            )

    def _check_read_timeouts_on_open_ports(self, port_results, observations):
        """Flag open ports that complete the TCP handshake but time out before sending a banner."""
        timeout_ports = [
            r.port
            for r in port_results
            if r.state == "open" and r.response_time_ms is None and "timeout" in (r.error or "").lower()
        ]

        if timeout_ports:
            observations.append(
                TimingObservation(
                    check_name="open_port_response_timeout",
                    ports_involved=timeout_ports,
                    description="Open port(s) accepted the TCP connection but timed out without sending data.",
                    evidence=f"Ports timing out after connect: {timeout_ports}",
                    confidence="low",
                    legitimate_reasons="Service may expect a custom client handshake before replying.",
                )
            )


class FingerprintReport:
    """Stores the complete network fingerprinting results for a target host."""

    def __init__(self, target, ports_checked, dry_run=False):
        self.target = target
        self.ports_checked = list(ports_checked)
        self.dry_run = dry_run
        self.scan_completed = False
        self.cancelled = False
        self.cancel_reason = None
        self.port_results = []
        self.tpot_correlation = None
        self.behaviour_observations = []
        self.timing_summary = {}
        self.timing_observations = []

    def get_all_matched_signatures(self):
        """Return a flat list of all matched signatures across all checked ports."""
        all_matches = []
        for port_res in self.port_results:
            for sig in port_res.matched_signatures:
                all_matches.append(sig.to_dict())
        if self.tpot_correlation is not None:
            all_matches.append(self.tpot_correlation.to_dict())
        return all_matches

    def to_dict(self):
        """Convert the full fingerprinting report into a dictionary."""
        return {
            "target": self.target,
            "scan_completed": self.scan_completed,
            "cancelled": self.cancelled,
            "cancel_reason": self.cancel_reason,
            "dry_run": self.dry_run,
            "ports_checked": self.ports_checked,
            "port_results": [r.to_dict() for r in self.port_results],
            "all_matched_signatures": self.get_all_matched_signatures(),
            "tpot_correlation": (
                self.tpot_correlation.to_dict() if self.tpot_correlation else None
            ),
            "behaviour_observations": [
                b.to_dict() for b in self.behaviour_observations
            ],
            "timing_summary": self.timing_summary,
            "timing_observations": [
                t.to_dict() for t in self.timing_observations
            ],
        }


class NetworkFingerprinter:
    """
    Coordinates banner grabbing, honeypot signature matching, port behaviour checks,
    and timing analysis across the configured TCP ports.
    """

    def __init__(
        self,
        ports=None,
        connect_timeout=3.0,
        read_timeout=3.0,
        rate_limit_delay=0.2,
        max_bytes=MAX_READ_BYTES,
        stop_file=None,
        socket_factory=None,
        db_path=None,
    ):
        self.ports = dict(ports) if ports is not None else dict(DEFAULT_PORTS)
        self.connect_timeout = max(0.1, float(connect_timeout))
        self.read_timeout = max(0.1, float(read_timeout))
        self.rate_limit_delay = max(0.0, float(rate_limit_delay))
        self.max_bytes = max_bytes
        self.stop_file = stop_file

        # Initialize helper components
        self.banner_grabber = BannerGrabber(
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            max_bytes=self.max_bytes,
            socket_factory=socket_factory,
        )
        self.signature_matcher = SignatureMatcher(db_path=db_path)
        self.behaviour_analyzer = PortBehaviourAnalyzer(
            expected_port_count=len(self.ports)
        )
        self.timing_analyzer = TimingAnalyzer()

    def _check_cancelled(self, stop_event=None, should_stop_callback=None):
        """Return a reason string if an emergency stop has been requested, or None otherwise."""
        if stop_event is not None and hasattr(stop_event, "is_set") and stop_event.is_set():
            return "Stop event triggered by kill switch"
        if callable(should_stop_callback) and should_stop_callback():
            return "Stop callback triggered by kill switch"
        if self.stop_file and os.path.exists(self.stop_file):
            return f"Emergency stop file detected ({self.stop_file})"
        return None

    def _planned_probe_name(self, service):
        """Return the probe name displayed when running in dry-run mode."""
        probes = {
            "SSH": "passive_greeting (dry-run)",
            "Telnet": "passive_greeting (dry-run)",
            "HTTP": "HTTP_HEAD (dry-run)",
            "SMB": "SMB2_NEGOTIATE (dry-run)",
            "Modbus": "MODBUS_READ_DEVICE_ID (dry-run)",
        }
        return probes.get(service, "passive_only (dry-run)")

    def run_scan(
        self,
        target="127.0.0.1",
        dry_run=False,
        stop_event=None,
        should_stop_callback=None,
    ):
        """Run the sequential network scan and return a FingerprintReport object."""
        port_list = list(self.ports.keys())
        report = FingerprintReport(target=target, ports_checked=port_list, dry_run=dry_run)

        if dry_run:
            for port, service in self.ports.items():
                planned = PortScanResult(target=target, port=port, service=service)
                planned.state = "dry_run"
                planned.probe_used = self._planned_probe_name(service)
                report.port_results.append(planned)
            report.scan_completed = True
            report.timing_summary = self.timing_analyzer.summarize_metrics([])
            return report

        try:
            for index, (port, service) in enumerate(self.ports.items()):
                # Check kill switch before probing each port
                cancel_reason = self._check_cancelled(stop_event, should_stop_callback)
                if cancel_reason:
                    report.cancelled = True
                    report.cancel_reason = cancel_reason
                    break

                # Wait between consecutive connection attempts for rate limiting
                if index > 0 and self.rate_limit_delay > 0:
                    time.sleep(self.rate_limit_delay)
                    cancel_reason = self._check_cancelled(stop_event, should_stop_callback)
                    if cancel_reason:
                        report.cancelled = True
                        report.cancel_reason = cancel_reason
                        break

                # Grab port banner and check for matching honeypot signatures
                port_result = self.banner_grabber.grab_banner(
                    target=target, port=port, service_name=service
                )
                if port_result.state == "open":
                    self.signature_matcher.match_port(port_result)

                report.port_results.append(port_result)

        except KeyboardInterrupt:
            report.cancelled = True
            report.cancel_reason = "Interrupted by user (Ctrl+C)"

        # Run cross-port correlation, behaviour heuristics, and timing analysis
        report.tpot_correlation = (
            self.signature_matcher.check_tpot_platform_correlation(report.port_results)
        )
        report.behaviour_observations = self.behaviour_analyzer.analyze(
            report.port_results
        )
        report.timing_summary = self.timing_analyzer.summarize_metrics(
            report.port_results
        )
        report.timing_observations = self.timing_analyzer.analyze(report.port_results)

        if not report.cancelled:
            report.scan_completed = True

        return report


def run_network_scan(
    target="127.0.0.1",
    dry_run=False,
    connect_timeout=3.0,
    read_timeout=3.0,
    rate_limit_delay=0.2,
    stop_event=None,
    should_stop_callback=None,
):
    """Run the network fingerprinter and return a dictionary of results."""
    scanner = NetworkFingerprinter(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        rate_limit_delay=rate_limit_delay,
    )
    return scanner.run_scan(
        target=target,
        dry_run=dry_run,
        stop_event=stop_event,
        should_stop_callback=should_stop_callback,
    ).to_dict()


# Alias functions for integration flexibility with main.py and scoring.py
scan_network = run_network_scan
fingerprint_target = run_network_scan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Fingerprinting Module")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP (default: 127.0.0.1)")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode without sending traffic")
    args = parser.parse_args()

    output = run_network_scan(target=args.target, dry_run=args.dry_run)
    print(json.dumps(output, indent=2))
