## About This Tool

CryWirelessMV is a command line (soon to be gui) wireless network pentest tool written in Python, built on top of Scapy for raw 802.11 frame crafting and injection. Made for security professionals or those who just want to learn ethical hacking. Use only on your own devices or with permission!

## Modules and Capabilities

### WiFi Attack Module

Scans nearby access points via dual-band channel hopping, then offers the following techniques against a chosen target:

- **Deauthentication Flood** — Force disconnects devices from the access point using deauth frames.
- **Authentication Request Flood** — Spam an access point with alot of fake authentication attempts.
- **Michael MIC (TKIP) Denial of Service** — Exploits the legacy TKIP countermeasure to force access points offline.
- **Probe Request Flood** — Floods a channel with probe traffic to test congestion handling.
- **Beacon Flood** — Generates alot of fake networks to flood scanners with fake APs.

### Handshake Capture Module

Captures the WPA/WPA2 4way handshake via deauthentication and EAPOL sniffing, then converts it directly into hashcat ready (22000) format for offline password auditing.

### IR Explorer Module

Drives an ESP32-based IR Transmitter over serial to browse, capture, and send infrared signals built for controlling IR devices.
To use IResp, get a Esp32 and flash the bin file on the repo and just connect via usb-serial, the IR led must be on **gpio16**

## Requirements

- Linux (Debian is fun)
- A wireless network adapter that supports monitor mode and packet injection
- Root privileges is required for wireless interface operations

## Authorized Use Only

For educational, research, and authorized security testing purposes only. Use only on systems you own or are explicitly authorized to test.

Provided "as is" without warranty. Users are solely responsible for complying with applicable laws and for any consequences arising from use of this software.

**Built by CodeLagging and Claude!**
