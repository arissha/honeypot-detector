# host_checks.py
# Honeypot Detector - Host Checks Module
# This part checks the machine it runs on for signs of a honeypot.

import os
import socket
import platform

# ----- Settings (things we look for) -----
VM_KEYWORDS = ["virtualbox", "vmware", "qemu", "kvm", "xen"]

VM_MAC_PREFIXES = {
    "08:00:27": "VirtualBox",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "52:54:00": "QEMU/KVM",
}

MIN_UPTIME_SECONDS = 3600   # less than 1 hour = suspicious
MIN_PROCESS_COUNT = 50      # less than 50 programs = suspicious

DEFAULT_HOSTNAMES = ["svr04", "localhost"]  # svr04 is Cowrie's default name

HONEYPOT_PATHS = [
    "/opt/cowrie", "/home/cowrie", "/etc/cowrie",
    "/opt/kippo", "/opt/dionaea", "/opt/conpot",
]

HONEYPOT_PROCESS_NAMES = ["cowrie", "kippo", "dionaea", "conpot"]


# ----- Helper functions -----

# Open a file and return its text. If it fails, return None so we don't crash.
def read_file(path):
    try:
        f = open(path, errors="ignore")
        text = f.read().strip()
        f.close()
        return text
    except OSError:
        return None


# Put a result into one standard shape so the scoring part can read it.
def make_result(check, suspicious, evidence, weight):
    result = {}
    result["check"] = check
    result["suspicious"] = suspicious
    result["evidence"] = evidence
    result["weight"] = weight
    return result


# ----- Checks -----

# Check 1: is the hardware maker a VM?
def check_vm_vendor():
    vendor = read_file("/sys/class/dmi/id/sys_vendor")
    product = read_file("/sys/class/dmi/id/product_name")
    if vendor is None and product is None:
        return None
    text = str(vendor) + " " + str(product)
    text = text.lower()
    found = False
    for word in VM_KEYWORDS:
        if word in text:
            found = True
    return make_result("vm_vendor", found, vendor + " / " + product, 10)


# Check 2: does the CPU report a hypervisor (means we are in a VM)?
def check_cpu_hypervisor():
    cpuinfo = read_file("/proc/cpuinfo")
    if cpuinfo is None:
        return None
    if "hypervisor" in cpuinfo:
        found = True
        evidence = "hypervisor flag found"
    else:
        found = False
        evidence = "no hypervisor flag"
    return make_result("cpu_hypervisor", found, evidence, 10)


# Check 3: does a network card have a known VM MAC address?
def check_mac_vendor():
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return None
    for iface in os.listdir(net_dir):
        mac = read_file(net_dir + "/" + iface + "/address")
        if not mac:
            continue
        prefix = mac[:8].lower()
        if prefix in VM_MAC_PREFIXES:
            maker = VM_MAC_PREFIXES[prefix]
            evidence = iface + " " + mac + " (" + maker + ")"
            return make_result("vm_mac", True, evidence, 10)
    return make_result("vm_mac", False, "no VM MAC prefix", 10)


# Check 4: are we inside a Docker container?
def check_container():
    if os.path.exists("/.dockerenv"):
        return make_result("container", True, "/.dockerenv exists", 15)
    cgroup = read_file("/proc/1/cgroup")
    if cgroup is None:
        cgroup = ""
    for word in ["docker", "kubepods", "lxc"]:
        if word in cgroup:
            return make_result("container", True, word + " in /proc/1/cgroup", 15)
    return make_result("container", False, "no container signs", 15)


# Check 5: has the machine only been on for a short time?
def check_uptime():
    data = read_file("/proc/uptime")
    if data is None:
        return None
    seconds = float(data.split()[0])
    hours = seconds / 3600
    suspicious = seconds < MIN_UPTIME_SECONDS
    evidence = "up " + str(round(hours, 1)) + " hours"
    return make_result("low_uptime", suspicious, evidence, 5)


# Check 6: are there very few programs running?
def check_process_count():
    if not os.path.isdir("/proc"):
        return None
    count = 0
    for name in os.listdir("/proc"):
        if name.isdigit():
            count = count + 1
    suspicious = count < MIN_PROCESS_COUNT
    evidence = str(count) + " processes running"
    return make_result("low_process_count", suspicious, evidence, 10)


# Check 7: are there any real human user accounts?
def check_real_users():
    passwd = read_file("/etc/passwd")
    if passwd is None:
        return None
    users = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) > 2 and parts[2].isdigit():
            uid = int(parts[2])
            if uid >= 1000 and uid < 65534:
                users.append(parts[0])
    suspicious = len(users) <= 1
    if users:
        evidence = "real users: " + str(users)
    else:
        evidence = "real users: none"
    return make_result("few_real_users", suspicious, evidence, 5)


# Check 8: is the hostname a default one?
def check_hostname():
    name = socket.gethostname().lower()
    suspicious = name in DEFAULT_HOSTNAMES
    evidence = "hostname is '" + name + "'"
    return make_result("default_hostname", suspicious, evidence, 10)


# Check 9: do any known honeypot folders exist?
def check_honeypot_paths():
    found = []
    for path in HONEYPOT_PATHS:
        if os.path.exists(path):
            found.append(path)
    suspicious = len(found) > 0
    if found:
        evidence = "found " + str(found)
    else:
        evidence = "none found"
    return make_result("honeypot_paths", suspicious, evidence, 25)


# Check 10: are any known honeypot programs running?
def check_honeypot_processes():
    found = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        if int(pid) == os.getpid():   # skip our own tool
            continue
        cmd = read_file("/proc/" + pid + "/cmdline")
        if not cmd:
            continue
        # cmdline uses a special separator between words
        parts = cmd.split("\x00")
        for name in HONEYPOT_PROCESS_NAMES:
            for part in parts:
                if " " in part:
                    continue
                if name in part.lower() and name not in found:
                    found.append(name)
    suspicious = len(found) > 0
    if found:
        evidence = "found " + str(found)
    else:
        evidence = "none found"
    return make_result("honeypot_processes", suspicious, evidence, 25)


# ----- Main runner -----
ALL_CHECKS = [
    check_vm_vendor,
    check_cpu_hypervisor,
    check_mac_vendor,
    check_container,
    check_uptime,
    check_process_count,
    check_real_users,
    check_hostname,
    check_honeypot_paths,
    check_honeypot_processes,
]


# Run every check and collect the results into a list.
def run_host_checks():
    if platform.system() != "Linux":
        print("[!] Host checks only support Linux for now. Skipping.")
        return []
    results = []
    for check in ALL_CHECKS:
        result = check()
        if result is not None:
            results.append(result)
    return results


# This runs only when I run this file directly (for testing).
if __name__ == "__main__":
    for r in run_host_checks():
        if r["suspicious"]:
            status = "SUSPICIOUS"
        else:
            status = "ok"
        print("[" + status + "] " + r["check"] + " -> " + r["evidence"])
