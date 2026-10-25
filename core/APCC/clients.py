import shlex
import subprocess
import time
from pathlib import Path

from .binpaths import get_bin


class _DummyResult:
    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.returncode = 1


def _run(cmd, timeout=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False,
                               timeout=timeout)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return _DummyResult()


class ClientManager:
    def __init__(self, iface, lease_file):
        self.iface = iface
        self.lease_file = Path(lease_file)



        self.filtered = {}
        self.static_ips = {}
        self.blocked_macs = set()



        self._name_cache = {}

    def _resolve_hostname(self, mac, ip):
        mac = mac.lower()
        if mac in self._name_cache:
            return self._name_cache[mac]
        if not ip or ip == "?":
            return None
        name = None





        res = _run(["avahi-resolve-address", ip], timeout=1.5)
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split(None, 1)
            if len(parts) == 2:
                name = parts[1].strip().rstrip(".")
        self._name_cache[mac] = name
        return name

    def _leases(self):
        out = []
        if not self.lease_file.is_file():
            return out
        try:
            for line in self.lease_file.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    _ts, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
                    out.append({"mac": mac, "ip": ip,
                                "hostname": hostname if hostname != "*" else "<unknown>"})
        except (OSError, UnicodeDecodeError, ValueError):
            pass
        return out

    def _hostapd_stations(self):
        macs = []
        res = _run([get_bin("hostapd_cli"), "-i", self.iface, "all_sta"])
        for line in res.stdout.splitlines():
            line = line.strip()
            if line and ":" in line and len(line) == 17:
                macs.append(line.lower())
        return macs

    def list_clients(self):
        leases = {l["mac"].lower(): l for l in self._leases()}
        connected_macs = self._hostapd_stations()
        clients = []
        seen = set()
        for mac in connected_macs:
            info = leases.get(mac, {})
            ip = self.static_ips.get(mac, info.get("ip", "?"))
            name = info.get("hostname", "<unknown>")
            if name == "<unknown>":
                name = self._resolve_hostname(mac, ip) or name
            clients.append({
                "mac": mac,
                "ip": ip,
                "name": name,
                "filtered": self.filtered.get(mac, True),
            })
            seen.add(mac)
        for mac, info in leases.items():
            if mac not in seen:
                ip = self.static_ips.get(mac, info.get("ip", "?"))
                name = info.get("hostname", "<unknown>")
                if name == "<unknown>":
                    name = self._resolve_hostname(mac, ip) or name
                clients.append({
                    "mac": mac,
                    "ip": ip,
                    "name": name,
                    "filtered": self.filtered.get(mac, True),
                })
        return clients

    def get_device_name(self, mac):
        mac = mac.lower()
        leases = {l["mac"].lower(): l for l in self._leases()}
        info = leases.get(mac)
        hostname = info.get("hostname") if info else None
        if hostname and hostname != "<unknown>":
            return hostname
        ip = self.static_ips.get(mac, info.get("ip") if info else None)
        return self._resolve_hostname(mac, ip)

    def is_filtered(self, mac):
        return self.filtered.get(mac.lower(), True)

    def toggle_filter(self, mac):
        mac = mac.lower()
        self.filtered[mac] = not self.filtered.get(mac, True)
        return self.filtered[mac]

    def is_blocked(self, mac):
        return mac.lower() in self.blocked_macs

    def deauth(self, mac, bursts=3):
        """One-shot kick. A single deauth only drops the client for a moment —
        it reassociates right away — so send a short burst. To keep a client
        off, use block() instead (adds it to hostapd's deny list)."""
        ok = False
        for _ in range(max(1, bursts)):
            res = _run([get_bin("hostapd_cli"), "-i", self.iface,
                        "deauthenticate", mac])
            ok = ok or res.returncode == 0
            time.sleep(0.2)
        return ok

    def block(self, mac):
        """Add the client to hostapd's runtime deny ACL, then deauth it, so it
        is kicked and refused on every reassociation attempt."""
        mac = mac.lower()
        self.blocked_macs.add(mac)
        ok = self._deny_acl("ADD_MAC", mac)
        self.deauth(mac)
        return ok

    def unblock(self, mac):
        mac = mac.lower()
        self.blocked_macs.discard(mac)
        return self._deny_acl("DEL_MAC", mac)

    def reapply_blocks(self):
        """Re-push the deny ACL after an AP (re)start, when hostapd's runtime
        state has been reset."""
        for mac in self.blocked_macs:
            self._deny_acl("ADD_MAC", mac)
            self.deauth(mac, bursts=1)

    def _deny_acl(self, op, mac):
        res = _run([get_bin("hostapd_cli"), "-i", self.iface,
                    "deny_acl", op, mac])
        return res.returncode == 0 and "FAIL" not in res.stdout.upper()

    def set_static_ip(self, mac, ip):
        self.static_ips[mac.lower()] = ip