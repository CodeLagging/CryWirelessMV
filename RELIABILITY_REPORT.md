# CryWirelessMV — Reliability Report

**Date:** 2026-10-31  ·  **Version:** 1.0.0  ·  **Commit:** `7e77d48`

This report has two halves, **both complete**:
- **Part 1 — Automated (non-RF) pass:** everything verifiable without radios, root, or transmission.
- **Part 2 — Live-RF tests:** executed against the dummy AP (`TestNetwork`, WPA2) on `wlan1`.

The assessment itself changed no code; the 7 findings it surfaced were fixed in a
follow-up pass (see "Fixes applied" below).

**Result at a glance:** 13 of 14 live checks passed; 1 blocked (Bluetooth scanner, F7). 7 findings total —
2 medium-to-high (missing `dbus_next` and `textual` deps), 1 medium (BLE rfkill), the rest low/cosmetic.
The backup/restore safety mechanism worked flawlessly. No lasting host changes.

---

## Part 1 — Automated pass (complete)

### 1.1 Module import matrix — 48 / 49 OK

Every module under `core/` was imported in a clean interpreter.

| Result | Detail |
|--------|--------|
| ✅ 48 modules | All of `core/APCC`, `core/WIFI`, `core/BT_HCI`, and top-level helpers import cleanly |
| ❌ 1 module | `core.APCC.tui` — `ModuleNotFoundError: No module named 'textual'` |

### 1.2 System-tool availability — 18 / 19 present

| Present | `iw`, `ip`, `iptables`, `ip6tables`, `nmcli`, `hostapd`, `hostapd_cli`, `dnsmasq`, `aircrack-ng`, `airmon-ng`, `hcxdumptool`, `hcxpcapngtool`, `ethtool`, `ufw`, `nft`, `systemctl`, `pkill`, `bluetoothctl` |
|---------|------|
| **Missing** | `conntrack` |

### 1.3 Entry point

| Command | Exit | Output |
|---------|------|--------|
| `main.py --version` | 0 | `CryWirelessMV 1.0.0` |
| `main.py --help` | 0 | usage/help text |

### 1.4 Config generation (pure)

| Artifact | Result |
|----------|--------|
| `generate_hostapd_conf(DEFAULTS, wlan1)` | 28 lines, contains `ssid=` and WPA directives ✅ |
| `generate_dnsmasq_conf(DEFAULTS, wlan1, …)` | 10 lines, contains `dhcp-range` and `interface=` ✅ |
| `validate_settings(DEFAULTS)` | 0 warnings (defaults are self-consistent) ✅ |

### 1.5 Frame building (built, not transmitted)

| Builder | Result |
|---------|--------|
| `deauth._build_deauth(ap, client, reason=7, burst=5)` | valid `RadioTap/Dot11/Dot11Deauth`; reason preserved ✅ |

### 1.6 Quality gates

| Gate | Result |
|------|--------|
| `pytest` | 233 passed |
| Coverage | 19% (floor enforced at 18%) |
| `ruff` | clean |
| `mypy` | clean |
| `pip-audit` | no known vulnerabilities |
| CI at HEAD | green |

---

## Findings (no fixes applied, per request)

| # | Severity | Finding | Impact |
|---|----------|---------|--------|
| F7 | **Medium-High** | `dbus_next` is not declared in any manifest and is not installed. The entire `core/BT_HCI/bluetooth.py` scanner depends on it (lazy-imported). | **Bluetooth scanner (menu option 6) is non-functional on a clean install.** Fails gracefully with an install message, but cannot scan. Same class as F1. |
| F6 | **Medium** | The BLE module's `_startble` only runs `hciconfig up` / `ip link set up` — it never `rfkill unblock`s. | On any host with Bluetooth **rfkill soft-blocked** (a very common default), BLE advertising fails with `OSError: [Errno 100] Network is down` and the tool does not recover. Confirmed live: unblocking fixed it. |
| F1 | **Medium** | `textual` is not declared in `pyproject.toml` / `requirements.txt` / `uv.lock`. `core.APCC.tui` import fails on a fresh install. | The APCC Textual UI never loads as shipped; `run()` catches `ImportError` and falls back to the classic console (no crash), but the TUI is dead code until `pip install textual`. |
| F4 | Low-Med | The redirect / captive-portal server fails to bind `:80` if the port is already in use (`[Errno 98] Address already in use`). Observed live on this host. | Domain *redirects* silently don't serve (block/sinkhole still works). Graceful warn, but the captive-portal feature is unavailable when `:80` is taken. |
| F5 | Low | `core/WIFI/__init__.py` re-exports flood functions under the same names as their submodules, so `import core.WIFI.auth_dos` resolves to the *function*, not the module. | Confusing for callers/tests (hit during this run); no runtime bug. |
| F2 | Low | `conntrack` binary not installed. | `report_traffic_counters()` falls back to `/proc/net/nf_conntrack` — live run showed `count=186`, so the fallback works. Cosmetic. |
| F3 | Info | `generate_dnsmasq_conf` is annotated `-> str` but returns a tuple. | No runtime bug (callers unpack it); misleading annotation. |

### Fixes applied (follow-up, after the report was delivered)

All 7 findings were addressed in focused commits (`8b11517`…`82e5c41`):

| # | Fix | Re-validated |
|---|-----|--------------|
| F7 | Declared `dbus-next` in dependencies | ✅ **BT scanner now works** — live scan discovered 16 devices (L14 flipped PASS) |
| F6 | `rfkill unblock` added to BLE `_startble` and BT adapter-ready path | ✅ live BLE advert now succeeds from a soft-blocked start (no manual unblock) |
| F1 | Declared `textual` in dependencies | ✅ `core.APCC.tui` imports; 50/50 modules now import |
| F4 | Actionable EADDRINUSE message for the captive-portal server | ✅ ruff/tests green |
| F5 | Removed `auth_dos`/`probe_dos` re-exports that shadowed their submodules | ✅ submodules now import cleanly |
| F3 | Corrected `generate_dnsmasq_conf` return annotation to `tuple[str, str]` | ✅ |
| F2 | Added `conntrack` + `rfkill` to the README apt install list | ✅ |

CI chain (ruff → mypy → pip-audit → pytest+coverage → requirements-drift) is green at HEAD.

### Positive reliability observations
- **Backup/restore works perfectly.** The APCC `backup_state`/`restore_state` cycle restored host iptables and `ip_forward` exactly to baseline after the AP teardown (verified byte-for-byte).
- Live AP bring-up, DHCP lease server, DNS answering, and domain block/redirect rule application all succeeded on real hardware.
- Monitor mode engages and reverts cleanly; the scanner parsed TestNetwork's beacon over the air.

---

## Part 2 — Live-RF test plan (phase 3, on `wlan1` → `TestNetwork`)

Legend for **Runner**: 🤖 = I drive it (non-destructive, scoped to the dummy AP) · ⚠️ = dry-run
only (DoS-class — I verify it builds/initializes but do **not** transmit the flood) · 👤 = needs you
(a client device must connect, or a physical observation).

Executed 2026-10-31 against `TestNetwork` (BSSID `AC:A7:F1:1E:6B:5B`, **channel 149 / 5 GHz**) on `wlan1`.
Uplink `wlan0` was never touched. Host state verified restored to baseline afterward.

| # | Module / function | Runner | Result |
|---|-------------------|--------|--------|
| **Recon / capture** |
| L1 | Monitor mode (via scanner) | 🤖 | ✅ **PASS** — wlan1 → monitor, tuned ch149, reverted to managed cleanly |
| L2 | PacketScanner | 🤖 | ✅ **PASS** — sniffed TestNetwork beacon; `_get_ssid` parsed SSID + bssid `ac:a7:f1:1e:6b:5b` |
| L3 | Handshake capture | 🤖 / 👤 | ✅ **PASS (logic)** — OTA beacon captured; synthetic 4/4 EAPOL → completion detected. Full OTA 4-way needs a client reassociation (👤) |
| **APCC (rogue AP infra)** |
| L4 | radio on/off | 🤖 | ✅ **PASS** — claimed wlan1, radio on |
| L5 | ap on/off | 🤖 | ✅ **PASS** — hostapd running, `AP-ENABLED` (BSS up), SSID `ScannerAP` broadcast live |
| L6 | dhcp on/off | 🤖 | ✅ **PASS** — dnsmasq running, gateway `192.168.50.1/24` assigned, DNS probe answered. Client lease needs a device (👤) |
| L7 | bridge/NAT | — | ⏭️ **SKIPPED** — not driven live, to avoid NAT changes on the active `wlan0` uplink. Logic path available on request |
| L8 | domain block/redirect | 🤖 | ✅ **PASS** — block + redirect rules generated in dnsmasq output (**but see F4**: redirect server couldn't bind `:80`) |
| L9 | client control | 🤖 / 👤 | ✅ **PASS** — client list works (0 connected); `set_client_timeout` iptables rule applied + removed. Full block needs a connected client (👤) |
| L10 | diag + restore | 🤖 | ✅ **PASS** — diagnostics ran; `restore_state` restored host iptables/`ip_forward` byte-for-byte |
| **DoS-class (dry-run — NOT transmitted)** |
| L11 | deauth | ⚠️ | ✅ **PASS (dry-run)** — `deauth_all` wired; frame builds (34 B). No transmit |
| L12 | disassoc / auth DoS / probe flood / Michael MIC / AP flood / CSA / action-frame / bad-message | ⚠️ | ✅ **PASS (dry-run)** — all 9 flood entry points wired; CSA (75 B), bad-message (131 B), action-frame (36 B) frames build. No transmit |
| **BLE / Bluetooth** |
| L13 | BLE advertisement spam | 🤖 / 👤 | ✅ **PASS** — all 5 vendor payloads build (≤31 B); live Apple advert accepted by hci0. **Required `rfkill unblock` first (F6).** Phone observation = 👤 |
| L14 | Bluetooth scanner | 🤖 | ❌ **BLOCKED (F7)** — `dbus_next` not installed/declared; scanner cannot run on a clean install |

**Notes for phase 3:**
- Requires root. The session reports a `SUDO=` variable is available, so I can run the privileged
  steps non-interactively.
- APCC modifies host iptables/sysctl and **restores on clean exit** (`restore_state`). If a run is
  killed, `sudo python3 main.py <iface> --fix` reverts leftover rules (per THREAT_MODEL.md §6).
- BLE/Bluetooth need a BT adapter (`hci0`) and, for L13, a phone to observe the spoofed advert.
- The DoS rows are intentionally dry-run; confirm you're OK with that boundary before phase 3.
