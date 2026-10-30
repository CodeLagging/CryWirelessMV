![CI](https://github.com/CodeLagging/CryWirelessMV/actions/workflows/ci.yml/badge.svg)
# CryWirelessMV

WiFi & BLE penetration testing for authorized security research.

## Features

- **WiFi Attack Module** — network scanning (dual-band channel hopping), deauthentication, authentication DoS, Michael MIC countermeasure DoS, and probe flood DoS
- **Handshake Capture Module** — automated WPA/WPA2 handshake capture with hashcat-ready (`hc22000`) export
- **BLE Spam Module** — BLE advertisement spoofing (Apple, Microsoft, Samsung, Google, FlipperZero), with single, spam, delayed, and chaos modes
- **IR Explorer Module** — IR remote database browser and command transmitter

## Requirements

- Linux (debian is fun)
- Python 3.10+
- Root/sudo privileges (for monitor mode, raw sockets, and HCI access ofc)
- A WiFi adapter that supports monitor mode (for WiFi modules)
- A Bluetooth adapter (for BLE module)


## Installation

**Install the following dependencies**
Update first
```
sudo apt update
```
Install Dependencies: 
```
sudo apt install -y \
  aircrack-ng \
  iw \
  iproute2 \
  net-tools \
  wireless-tools \
  bluez \
  bluetooth \
  hcxtools \
  build-essential \
  python3-dev \
  libpcap-dev
```
Install Python Dependencies (venv can be skipped):
```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Environment Variables

CryWirelessMV needs no secrets. The variables it touches are listed in
[`.env.example`](.env.example):

| Variable | Purpose |
|----------|---------|
| `SUDO_UID`, `SUDO_GID` | Set automatically by `sudo`; used to return generated files to your ownership instead of root's. Not user-configured. |
| `PYTHONPATH` | Set by `core/set_path.py` so `core.*` imports resolve regardless of the working directory. |
| `CWMV_LOG_DIR` | Optional. Directory for the rotating forensic log (default `~/.cwmv/logs`). |
| `APCC_CLASSIC` | Optional. Set to `1` to force the classic console UI instead of the Textual TUI. |

## Usage

```bash
sudo python3 main.py
```

### Run with Docker

The whole app comes up with one command (no external services needed):

```bash
docker compose run --rm cwmv
```

This builds the image and starts the interactive menu with `--privileged`, host
networking, and USB passthrough so monitor mode and HCI access work. See
[`docker-compose.yml`](docker-compose.yml) for details.

## Architecture

```
CryWirelessMV/
├── main.py                   # Entry point — module selection menu
├── banner.py                 # Startup banner and OS check
├── debugs.py                 # Coloured debug/log printer
└── core/
    ├── wifi_module.py        # WiFi attack module entry point
    ├── WIFI/
    │   ├── scanner.py        # Dual-band channel-hopping packet scanner
    │   ├── attack_module.py  # Attack menu and dispatcher
    │   ├── deauth.py         # 802.11 deauthentication flood
    │   ├── auth_dos.py       # Authentication frame DoS
    │   ├── michael_mic.py    # Michael MIC countermeasure DoS
    │   ├── probe_dos.py      # Probe response flood
    │   ├── handshake_module.py  # WPA/WPA2 handshake capture → hc22000
    │   └── ...               # csa_attack, disassoc, action_frame, ap_flood
    ├── BT_HCI/
    │   ├── ble_module.py     # BLE advertisement spammer (HCI raw socket)
    │   ├── ble_constants.py  # Vendor advertisement payloads
    │   └── bluetooth.py      # Classic BT scanner
    └── APCC/                 # AP Control Centre — interactive rogue AP
        ├── scanner_ap.py     # ScannerAP: AP lifecycle, radio, watchdog, run loop
        ├── ap_cmd_handlers.py  # APCommandHandlersMixin: all interactive commands
        ├── line_editor.py    # LineEditorMixin: readline, history, Tab-completion
        ├── netops.py         # iptables, NAT, policy routing, diagnostics
        ├── tui.py            # Textual TUI (falls back to classic console)
        ├── confgen.py        # hostapd / dnsmasq config generation
        ├── clients.py        # Connected client tracking and control
        ├── domain_control.py # DNS blocking and redirect rules
        ├── logging_ap.py     # Live packet logger with category filters
        └── settings.py       # Persistent AP settings (JSON)
```

**Data flow:**
`main.py` → selects module → `ScannerAP.run()` → `_startup()` (load settings, init logger) → `_run_classic()` / `run_tui()` → interactive REPL (`_read_line` → `CommandRouter.parse` → `_cmd_*`) → `netops` for iptables/routing operations.

**Key design decisions:**
- All subprocess calls use list form (no `shell=True`) and interface names are validated with `IFACE_REGEX` before use.
- `ScannerAP` inherits `LineEditorMixin` (readline) and `APCommandHandlersMixin` (commands) to keep the core AP logic under 700 LOC.
- The watchdog thread polls `hostapd.poll()` every 2s and auto-reconnects with exponential backoff on unexpected exit.

## Security

- [SECURITY.md](SECURITY.md) — supported versions and how to report a vulnerability
- [THREAT_MODEL.md](THREAT_MODEL.md) — trust boundaries, untrusted input, and mitigations
- [CHANGELOG.md](CHANGELOG.md) — notable changes per release

## License

Licensed under the GNU General Public License v3.0 (GPLv3). See [LICENSE](LICENSE) for details.

---

## Legal Disclaimer

This tool is provided **for educational and authorized security testing purposes only**. It is intended to help individuals learn about wireless network security, BLE protocols, and penetration testing concepts in legal, controlled environments — such as your own equipment or networks you have **explicit written permission** to test.

The author(s) and contributors of this project:
- Take **no responsibility** for any misuse of this software
- Provide this tool **"as is"**, without warranty of any kind
- Do **not condone** illegal use of this tool in any form

**By using this software, you agree that you are solely responsible for ensuring your use complies with all applicable local, state, and federal laws.**

**For educational purposes only.**
