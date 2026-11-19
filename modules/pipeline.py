"""Glue between Member B (network), Member C (host) and Member D (scoring).

B's network scanner returns a report dictionary and C's host scanner returns a
list of dictionaries. This module converts both into ``Finding`` objects, runs
the scoring engine and returns everything the CLI needs.

Two design decisions are worth explaining in the oral interview:

1. Correlated evidence is counted once. The three virtual-machine checks
   (DMI vendor, CPU hypervisor flag, MAC prefix) all detect the same fact, so
   they are folded into one "virtualisation" finding. Otherwise an ordinary VM
   would score as a honeypot just because three checks agree.
2. Host checks inspect the machine the tool runs on. They only say something
   about the target when the target is this machine, so they are skipped for
   remote targets.
"""

import ipaddress
import platform
import re

from modules import host_scan, network_scan
from modules.scoring import Finding, calculate_score

# --- how B's and C's labels become weights (0 - 1) --------------------------
SIGNATURE_WEIGHT = {"strong": 0.80, "moderate": 0.50, "weak": 0.20}
OBSERVATION_WEIGHT = {"high": 0.50, "moderate": 0.30, "low": 0.12}
# C's weights are points (5 - 25). Multiplying by 0.03 gives 0.15 - 0.75, so a
# known honeypot folder (25) is strong evidence and a short uptime (5) is weak.
HOST_WEIGHT_SCALE = 0.03

VM_CHECKS = ("vm_vendor", "cpu_hypervisor", "vm_mac")

HOST_DESCRIPTIONS = {
    "vm_vendor": "Read the hardware vendor and product name (DMI)",
    "cpu_hypervisor": "Look for the hypervisor flag in /proc/cpuinfo",
    "vm_mac": "Compare network card MAC prefixes with known VM vendors",
    "container": "Look for /.dockerenv and container names in cgroups",
    "low_uptime": "Read the system uptime",
    "low_process_count": "Count running processes",
    "few_real_users": "Count real user accounts (names are not stored)",
    "default_hostname": "Compare the hostname with default honeypot names",
    "honeypot_paths": "Look for known honeypot folders (existence only)",
    "honeypot_processes": "Look for known honeypot process names",
}

PROBE_DESCRIPTIONS = {
    "SSH": "Connect and read the greeting banner",
    "Telnet": "Connect and read the login prompt",
    "HTTP": "Send one HTTP HEAD request and read the headers",
    "SMB": "Send one read-only SMB2 negotiate request",
    "Modbus": "Send one read-only Modbus device-identification request",
}

_MAC_TAIL = re.compile(r"((?:[0-9a-f]{2}:){3})(?:[0-9a-f]{2}:){2}[0-9a-f]{2}", re.I)


# ------------------------------------------------------------------- helpers --

def is_local_target(target):
    """True for localhost / loopback addresses only."""
    name = str(target).strip().lower()
    if name in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _short(text, limit=140):
    text = " ".join(str(text).split())  # one line, no line breaks
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _sanitise_host_evidence(check, evidence, suspicious):
    """Keep reports free of personal identifiers (account names, full MACs)."""
    if check == "few_real_users":
        names = re.findall(r"'([^']*)'", str(evidence))
        return f"{len(names)} real user account(s) found (names not stored)"
    if check == "vm_mac":
        return _MAC_TAIL.sub(r"\1xx:xx:xx", str(evidence))
    if check == "default_hostname" and not suspicious:
        return "hostname is not a known default"
    return _short(evidence)


def _host_weight(raw_weight):
    return min(1.0, float(raw_weight) * HOST_WEIGHT_SCALE)


# ----------------------------------------------------------------- converters --

def host_results_to_findings(results):
    """Convert C's list of {check, suspicious, evidence, weight} into Findings."""
    findings = []
    vm_items = []

    for item in results:
        check = item["check"]
        if check in VM_CHECKS:
            vm_items.append(item)
            continue
        suspicious = bool(item["suspicious"])
        findings.append(
            Finding(
                check=check,
                category="host",
                triggered=suspicious,
                weight=_host_weight(item["weight"]),
                reason=HOST_DESCRIPTIONS.get(check, check)
                + (" - suspicious" if suspicious else " - normal"),
                confidence=1.0,
                evidence=_sanitise_host_evidence(check, item["evidence"], suspicious),
            )
        )

    if vm_items:
        hits = [i for i in vm_items if i["suspicious"]]
        findings.append(
            Finding(
                check="virtualisation",
                category="host",
                triggered=bool(hits),
                weight=max(_host_weight(i["weight"]) for i in vm_items),
                reason=(
                    "System looks virtualised (" + ", ".join(i["check"] for i in hits) + ")"
                    if hits
                    else "No sign of a virtual machine"
                ),
                confidence=1.0,
                evidence=_short(
                    "; ".join(
                        _sanitise_host_evidence(i["check"], i["evidence"], True) for i in hits
                    )
                ),
            )
        )
    return findings


def network_report_to_findings(report):
    """Convert B's FingerprintReport dictionary into Findings."""
    findings = []

    # Signatures: if several rules match the same honeypot on the same port
    # they describe the same observation, so keep only the strongest.
    best = {}
    for sig in report.get("all_matched_signatures", []):
        key = (sig["honeypot"], sig["port"])
        weight = SIGNATURE_WEIGHT.get(sig["strength"], SIGNATURE_WEIGHT["weak"])
        if key not in best or weight > best[key][0]:
            best[key] = (weight, sig)

    for (honeypot, port), (weight, sig) in best.items():
        findings.append(
            Finding(
                check=sig["signature_id"].lower(),
                category="network",
                triggered=True,
                weight=weight,
                reason=f"{honeypot} signature on port {port}: {sig['description']}",
                confidence=1.0,
                evidence=_short(sig["evidence"]),
            )
        )

    matched_ports = {sig["port"] for _, sig in best.values()}
    for res in report.get("port_results", []):
        if res.get("state") == "open" and res["port"] not in matched_ports:
            findings.append(
                Finding(
                    check=f"signature_{res['service'].lower()}_{res['port']}",
                    category="network",
                    triggered=False,
                    weight=SIGNATURE_WEIGHT["moderate"],
                    reason=f"No honeypot signature matched on port {res['port']} ({res['service']})",
                )
            )

    for obs in report.get("behaviour_observations", []) + report.get("timing_observations", []):
        findings.append(
            Finding(
                check=obs["check_name"],
                category="network",
                triggered=True,
                weight=OBSERVATION_WEIGHT.get(obs["confidence"], OBSERVATION_WEIGHT["low"]),
                reason=obs["description"],
                confidence=1.0,
                evidence=_short(obs["evidence"]),
            )
        )
    return findings


# ------------------------------------------------------------------ host run --

def run_host_checks_safely(notes):
    """Run C's checks one by one so a single failing check cannot stop the scan."""
    if platform.system() != "Linux":
        notes.append("Host checks skipped: they only support Linux.")
        return []
    results = []
    for check in host_scan.ALL_CHECKS:
        try:
            result = check()
        except Exception as exc:  # noqa: BLE001 - one bad check must not stop the scan
            notes.append(f"Host check {check.__name__} failed and was skipped ({type(exc).__name__}).")
            continue
        if result is not None:
            results.append(result)
    return results


# --------------------------------------------------------------- planning ----

def planned_checks(ports=None, run_host=True):
    """Rows for reporting.print_dry_run: (module, check, description)."""
    rows = []
    for port, service in (ports or network_scan.DEFAULT_PORTS).items():
        rows.append(("network", f"{service.lower()}_{port}", PROBE_DESCRIPTIONS.get(service, "Read the banner")))
    rows.append(("network", "behaviour+timing", "Compare ports with each other and measure response times"))
    if run_host:
        for check in host_scan.ALL_CHECKS:
            name = check.__name__.replace("check_", "")
            rows.append(("host", name, "Local read-only check"))
    return rows


# --------------------------------------------------------------------- main --

def run_full_scan(
    target="127.0.0.1",
    dry_run=False,
    ports=None,
    run_host=None,
    connect_timeout=3.0,
    read_timeout=3.0,
    rate_limit_delay=0.2,
    stop_file=None,
    stop_event=None,
    should_stop_callback=None,
):
    """Run network + host checks and score them.

    Returns a dict: findings, score (ScoreResult), notes, planned, dry_run.
    Nothing is sent and no check runs when dry_run is True.
    """
    notes = []
    if run_host is None:
        run_host = is_local_target(target)
    if not run_host:
        notes.append("Host checks skipped: they describe the machine running the tool, not the remote target.")

    ports = dict(ports) if ports is not None else dict(network_scan.DEFAULT_PORTS)
    planned = planned_checks(ports, run_host)

    if dry_run:
        return {"findings": [], "score": None, "notes": notes, "planned": planned, "dry_run": True}

    scanner = network_scan.NetworkFingerprinter(
        ports=ports,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        rate_limit_delay=rate_limit_delay,
        stop_file=stop_file,
    )
    report = scanner.run_scan(
        target=target,
        stop_event=stop_event,
        should_stop_callback=should_stop_callback,
    ).to_dict()

    findings = network_report_to_findings(report)
    if run_host:
        findings += host_results_to_findings(run_host_checks_safely(notes))

    if report["cancelled"]:
        notes.append(f"Scan stopped early ({report['cancel_reason']}). Results are partial.")
    if not any(r["state"] == "open" for r in report["port_results"]):
        notes.append("No monitored port was open, so the network evidence is empty.")

    return {
        "findings": findings,
        "score": calculate_score(findings),
        "notes": notes,
        "planned": planned,
        "dry_run": False,
    }
