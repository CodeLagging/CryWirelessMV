# Threat Model

This document describes the trust boundaries, assets, and mitigations for
CryWirelessMV. It complements [SECURITY.md](SECURITY.md), which covers the
vulnerability-reporting process.

## 1. Privilege model

CryWirelessMV runs as **root** (`sudo python3 main.py`). Root is required for:

- Monitor mode and raw 802.11 frame injection (WiFi modules)
- Raw HCI sockets for BLE advertisement and scanning (`core/BT_HCI/`)
- `iptables` / `ip` / `sysctl` manipulation for the rogue-AP NAT path (`core/APCC/`)

The process does **not** drop privileges after startup. Anyone who can run the
tool, or inject code into it, has root. Only run it on hardware you own.

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Root shell / host integrity | A bug in packet parsing or a subprocess call runs as root |
| Captured handshakes (`hc22000`) | Contain material usable for offline password cracking |
| Session pcaps / DNS logs | Reveal traffic of devices connected to the test AP |
| The host's original network config | The tool rewrites iptables/sysctl and must restore them on exit |

## 3. Trust boundaries & untrusted input

### 3a. Trusted inputs (operator-controlled)

These originate from the authorized operator and are trusted, but still validated
to catch mistakes before they reach a privileged subprocess:

- **CLI arguments** — `main.py` / `scanner_ap.py` argv (interface name, save path, `--fix`). Interface names pass `validate_iface()`.
- **Settings JSON** — `SCAN_inspector/conf/*.json` loaded by `core/APCC/settings.py`; every field is re-checked by `validate_settings()` on load, which corrects out-of-range values rather than trusting them.
- **Domain block/redirect lists** — operator-provided patterns parsed by `core/APCC/domain_filter.py::compile_pattern` (raises `BadPattern` on malformed input) and `domain_control.py`.

### 3b. Untrusted inputs (over-the-air / external)

| Boundary | Untrusted input | Entry point | Mitigation |
|----------|-----------------|-------------|------------|
| Over-the-air 802.11 frames | Attacker-controlled beacons, probes, EAPOL | `scapy.sniff()` in `core/WIFI/scanner.py`, `core/APCC/logging_ap.py` | Parsing is read-only; fields are never passed to a shell; malformed frames are caught per-packet |
| Over-the-air BLE advertisements | Arbitrary advertisement payloads | `core/BT_HCI/bluetooth.py` | Parsed into `DeviceRecord` dataclasses; no eval/shell use |
| User-supplied interface names | `wlanX` typed at the prompt | `ScannerAP(iface=...)`, every `netops`/`firewall` call | `validate_iface()` in `core/validators.py` — rejects anything outside `^[a-zA-Z0-9_-]{1,15}$` before it reaches a subprocess |
| User-supplied MAC / channel / SSID / IP range | Prompt input | `core/APCC/ap_cmd_handlers.py`, `settings.py` | `validate_mac` / `is_valid_channel` / `is_valid_ssid` / `is_valid_ip_range` in `core/validators.py` |
| System tool output (`iw`, `iptables`, `nmcli`) | Parsed command output | `core/APCC/netops.py`, `firewall.py` | Output parsed defensively; failures degrade to warnings, not crashes |

## 4. Subprocess safety & privilege escalation

- **No `shell=True` anywhere.** Every external command is invoked with an argv
  list (`subprocess.run([...])` in `core/APCC/netutil.py::_run`, `core/WIFI/scanner.py`),
  so interface names and MACs cannot break out into shell metacharacters even if
  validation were bypassed. This is the primary reason the input validators below
  are defense-in-depth rather than the only line of defense.
- Commands run with bounded timeouts and failures return a dummy result rather
  than raising, so a missing tool cannot crash a teardown path mid-way and
  leave the host's network in a broken state.
- **Privilege model:** the process runs as root and does **not** drop privileges
  after startup, because monitor mode, raw sockets, and `iptables`/`ip`/`sysctl`
  all require it for the life of the session. Consequences:
  - A compromised or trojaned `hostapd` / `dnsmasq` / `iptables` / `iw` binary on
    the host runs with root privileges. The tool resolves binaries from `PATH`
    (`core/APCC/binpaths.py::get_bin`); operators are responsible for the
    integrity of those system tools (verify package signatures).
  - A memory-safety bug in `scapy` or BlueZ reachable via crafted radio input
    (§3b) would execute in a root process. Keep dependencies patched — `pip-audit`
    runs in CI and Dependabot opens weekly update PRs.

### 4a. Input validators (defense-in-depth), by source file

Each mitigation maps to a reviewable function in `core/validators.py`:

| Validator | Guards |
|-----------|--------|
| `validate_iface()` / `is_valid_iface()` | interface names before any subprocess/iptables call |
| `validate_mac()` / `is_valid_mac()` | client MAC in `client` deauth/block/timeout commands |
| `is_valid_channel()` | WiFi channel in `settings.validate_settings` |
| `is_valid_ip_range()` | AP subnet (CIDR) before `ipaddress`/`ip addr` use |
| `is_valid_ssid()` | 802.11 SSID length (≤32 bytes) before hostapd config generation |

## 5. Non-goals

- The tool does **not** sandbox the system binaries it calls (`hostapd`,
  `dnsmasq`, `iptables`). A compromised copy of those on the host runs as root.
- It does not defend against a malicious operator — it is an offensive tool by
  design and assumes the person running it is authorized to do so.
- It does not encrypt captured artifacts at rest; protect the save directory
  with filesystem permissions.

## 6. Residual risks

- A memory-safety bug in `scapy` or `BlueZ` reachable via crafted radio input
  would execute in a root process. Keep dependencies patched (`pip-audit` runs
  in CI; Dependabot opens weekly update PRs).
- If the tool is killed with `SIGKILL`, the restore path in
  `netops.restore_state()` does not run and the host keeps the modified
  iptables/sysctl state until `--fix` is run.
