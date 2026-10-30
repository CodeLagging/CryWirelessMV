# Security Policy

## Scope

This policy covers vulnerabilities **in CryWirelessMV itself** — bugs in the tool's own code that could be exploited. It does not cover misuse of the tool against third-party networks, which is illegal and outside the scope of this project.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ Active |
| Tagged releases | ✅ Critical fixes only |
| Older branches | ❌ |

## Threat Model

CryWirelessMV runs as root and performs raw packet injection, raw HCI socket access, and subprocess calls to system tools. Its attack surface as a piece of software is:

| Threat | Mitigation |
|--------|-----------|
| Interface name injection into subprocess calls | All interface names validated with `IFACE_REGEX` before use |
| Shell injection via subprocess | All subprocess calls use list form — `shell=False` everywhere |
| SSID / config injection into hostapd config | Config values written via `confgen.py`; special chars escaped |
| Privilege escalation after startup | No privilege drop; tool requires root for its core functions — only run on hardware you own |
| Sensitive capture output exfiltration | Session files (pcap, hc22000, leases) written to local paths only; no network upload |
| Dependency supply-chain compromise | `uv.lock` pins all transitive deps; `pip-audit` runs in CI |

Known limitation: the tool does not sandbox its own subprocesses. A compromised `hostapd` or `dnsmasq` binary on the system would run with root privileges.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

1. Open a private advisory at: https://github.com/CodeLagging/CryWirelessMV/security/advisories/new
2. Include: affected version, steps to reproduce, and impact.
3. If you have a suggested fix, include it — patches are welcome.

**Response timeline:**
- Acknowledgement: within 5 business days
- Patch or mitigation: within 30 days for critical issues; 90 days for lower severity

## Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Using it against networks, devices, or systems you do not own or have explicit written permission to test is illegal under computer fraud laws in most jurisdictions.

The authors accept no liability for misuse.
