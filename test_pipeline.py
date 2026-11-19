import socket
import threading
import unittest
from unittest import mock

from modules import host_scan
from modules.pipeline import (
    host_results_to_findings,
    is_local_target,
    run_full_scan,
)

COWRIE_SSH = b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n"
COWRIE_TELNET = b"\xff\xfd\x1f\xff\xfd\x18Debian GNU/Linux 7\r\nsvr04 login: "
NORMAL_SSH = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"


class FakeService(threading.Thread):
    """Sends a payload to every client. Used as a stand-in for a real service."""

    def __init__(self, payload):
        super().__init__(daemon=True)
        self.payload = payload
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def run(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(self.payload)
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self):
        self.running = False
        self.sock.close()


def scan(services, **kwargs):
    """services: list of (payload, service_name). Returns run_full_scan result."""
    fakes = [(FakeService(p), name) for p, name in services]
    for f, _ in fakes:
        f.start()
    try:
        ports = {f.port: name for f, name in fakes}
        return run_full_scan(
            "127.0.0.1", ports=ports, run_host=False,
            connect_timeout=1, read_timeout=1, rate_limit_delay=0, **kwargs
        )
    finally:
        for f, _ in fakes:
            f.stop()


def hr(check, suspicious, evidence="x", weight=10):
    return {"check": check, "suspicious": suspicious, "evidence": evidence, "weight": weight}


class NetworkIntegrationTests(unittest.TestCase):
    def test_cowrie_like_target_scores_high(self):
        result = scan([(COWRIE_SSH, "SSH"), (COWRIE_TELNET, "Telnet")])
        score = result["score"]
        checks = {c["check"] for c in score.contributions}
        self.assertIn("cowrie-ssh-01", checks)
        self.assertIn("cowrie-telnet-01", checks)
        self.assertGreaterEqual(score.likelihood_pct, 75.0)

    def test_normal_ssh_server_scores_low(self):
        result = scan([(NORMAL_SSH, "SSH")])
        self.assertLess(result["score"].likelihood_pct, 25.0)
        self.assertEqual(result["score"].checks_triggered, 0)

    def test_closed_ports_are_reported_in_notes(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        result = run_full_scan("127.0.0.1", ports={closed: "SSH"}, run_host=False,
                               connect_timeout=1, read_timeout=1, rate_limit_delay=0)
        self.assertTrue(any("No monitored port was open" in n for n in result["notes"]))

    def test_stop_file_cancels_and_notes_partial(self):
        import os, tempfile
        with tempfile.NamedTemporaryFile() as stop:
            result = scan([(NORMAL_SSH, "SSH")], stop_file=stop.name)
        self.assertTrue(any("partial" in n for n in result["notes"]))
        self.assertTrue(os.path.basename(stop.name))


class HostConversionTests(unittest.TestCase):
    def test_vm_checks_are_counted_once(self):
        findings = host_results_to_findings([
            hr("vm_vendor", True, "QEMU / Standard PC"),
            hr("cpu_hypervisor", True),
            hr("vm_mac", True),
        ])
        vm = [f for f in findings if f.check == "virtualisation"]
        self.assertEqual(len(vm), 1)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(vm[0].strength, 0.30)

    def test_honeypot_paths_are_strong(self):
        findings = host_results_to_findings([hr("honeypot_paths", True, "found ['/opt/cowrie']", 25)])
        self.assertAlmostEqual(findings[0].strength, 0.75)

    def test_usernames_are_not_stored(self):
        f = host_results_to_findings([hr("few_real_users", False, "real users: ['alice', 'bob']", 5)])[0]
        self.assertNotIn("alice", f.evidence)
        self.assertIn("2", f.evidence)

    def test_mac_address_is_masked(self):
        f = host_results_to_findings([hr("vm_mac", True, "eth0 08:00:27:ab:cd:ef (VirtualBox)")])[0]
        self.assertIn("08:00:27", f.evidence)
        self.assertNotIn("ab:cd:ef", f.evidence)

    def test_normal_hostname_not_stored(self):
        f = host_results_to_findings([hr("default_hostname", False, "hostname is 'johns-laptop'")])[0]
        self.assertNotIn("johns", f.evidence)

    def test_failing_host_check_does_not_stop_the_scan(self):
        def boom():
            raise TypeError("bad check")
        with mock.patch.object(host_scan, "ALL_CHECKS", [boom, host_scan.check_hostname]):
            result = run_full_scan("127.0.0.1", ports={1: "SSH"}, run_host=True,
                                   connect_timeout=0.2, read_timeout=0.2, rate_limit_delay=0)
        self.assertTrue(any("boom" in n for n in result["notes"]))
        self.assertTrue(any(f.check == "default_hostname" for f in result["findings"]))


class SafetyTests(unittest.TestCase):
    def test_dry_run_opens_no_sockets_and_reads_nothing(self):
        with mock.patch("socket.socket", side_effect=AssertionError("socket opened")), \
             mock.patch.object(host_scan, "read_file", side_effect=AssertionError("file read")):
            result = run_full_scan("127.0.0.1", dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["findings"], [])
        self.assertGreater(len(result["planned"]), 5)

    def test_remote_target_skips_host_checks(self):
        result = run_full_scan("192.0.2.10", dry_run=True)
        self.assertFalse(any(row[0] == "host" for row in result["planned"]))
        self.assertTrue(any("Host checks skipped" in n for n in result["notes"]))

    def test_is_local_target(self):
        for ok in ("127.0.0.1", "localhost", "::1", "127.5.5.5"):
            self.assertTrue(is_local_target(ok), ok)
        for bad in ("192.168.1.5", "example.com", "8.8.8.8", ""):
            self.assertFalse(is_local_target(bad), bad)


if __name__ == "__main__":
    unittest.main()
