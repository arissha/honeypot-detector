"""Demo of Member D's modules with fake findings - use it for README screenshots."""
import sys

from modules.scoring import Finding, calculate_score
from modules.reporting import print_report, print_dry_run, save_report

TARGET = "127.0.0.1"

findings = [
    Finding("ssh_banner_cowrie", "network", True, 0.85,
            "SSH banner matches the default Cowrie signature", 0.9, "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"),
    Finding("all_ports_open", "network", True, 0.60,
            "Every probed port accepted a connection", 0.8),
    Finding("response_timing", "network", True, 0.25,
            "Response times were suspiciously uniform", 0.6),
    Finding("docker_env", "host", True, 0.40,
            "/.dockerenv present (container)", 1.0),
    Finding("short_uptime", "host", True, 0.20,
            "Uptime under 10 minutes", 0.7),
    Finding("cowrie_paths", "host", False, 0.90,
            "No Cowrie directories found"),
    Finding("telnet_banner", "network", False, 0.70,
            "Telnet banner looks normal"),
]

planned = [
    ("network", "banner_grab", "Connect to ports 22/23/80/445/502 and read the banner"),
    ("network", "port_behaviour", "Check whether every port accepts connections"),
    ("network", "response_timing", "Measure reply time per port"),
    ("host", "vm_container", "Look for /.dockerenv, DMI strings, hypervisor flag"),
    ("host", "honeypot_paths", "Look for known honeypot folders (metadata only)"),
]

if "--dry-run" in sys.argv:
    print_dry_run(TARGET, planned, ports=[22, 23, 80, 445, 502])
else:
    result = calculate_score(findings)
    print_report(TARGET, result)
    paths = save_report(TARGET, result, findings)
    print("\nSaved:", *paths, sep="\n  ")
