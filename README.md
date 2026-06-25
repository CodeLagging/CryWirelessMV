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

If you use raspberry pi or any arm64 systems, use the one in ``for-aarch64`` folder or ``mv ./for-aarch64 ./core``
## Usage

```bash
sudo python3 main.py
```

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



### Made by me and claude!
