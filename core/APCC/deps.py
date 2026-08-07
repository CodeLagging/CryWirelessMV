import os
import shutil





REQUIRED_BINS = ["iptables", "ip", "iw"]


def _install_hint():
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
    except Exception:
        content = ""
    if "debian" in content or "ubuntu" in content:
        return "sudo apt-get update && sudo apt-get install -y iptables iproute2 iw"
    if "fedora" in content or "rhel" in content or "centos" in content:
        return "sudo dnf install -y iptables iproute iw"
    if "arch" in content:
        return "sudo pacman -S --needed iptables iproute2 iw"
    return "install iptables, iproute2, and iw using your distro's package manager"


def check_root(debug):
    if os.geteuid() != 0:
        debug("warn", "Not running as root (EUID != 0). hostapd/dnsmasq "
                       "binding and every iptables/ip rule this tool adds "
                       "need root or the equivalent capabilities — if "
                       "anything (NAT, DHCP, the AP itself) reports success "
                       "but doesn't actually work, this is the first thing "
                       "to rule out. Re-run with sudo, or grant the specific "
                       "capabilities (CAP_NET_ADMIN, CAP_NET_RAW) if you're "
                       "intentionally running unprivileged.")


def check_dependencies(debug):
    missing = [b for b in REQUIRED_BINS if shutil.which(b) is None]
    if not missing:
        return True
    debug("critical", f"Missing required tool(s): {', '.join(missing)}")
    debug("critical", f"Install with: {_install_hint()}")
    return False
