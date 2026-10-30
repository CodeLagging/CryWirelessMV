# Changelog

All notable changes to CryWirelessMV are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [v1.0.0] — 2026-10-30

First semantic-versioned release. Reconciles the fragmented version strings
(pyproject, banner, tags) onto a single `1.0.0` source of truth and ships an
automated tag-triggered x64 release workflow.

### Added
- Automated tag-triggered x64 release workflow (`.github/workflows/release.yml`)
- `core/_version.py` single source of truth; `main.py --version` / `-V` flag
- Unit tests for `CommandRouter`, `settings.validate_settings`, and domain filter/control (66 tests; coverage floor raised to 15%)
- `THREAT_MODEL.md` — trust boundaries, untrusted radio input, subprocess-safety model
- `core/log_config.py` — structured logging (rotating file handler + levels); `debug()` now mirrors to it
- `docker-compose.yml` — one-command startup (`docker compose run --rm cwmv`) with USB/host passthrough
- `.env.example` + README "Environment Variables" section
- Split `netops.py` (1099 LOC) into focused modules: `netutil.py`, `firewall.py`, `routing.py`, `diag.py`
- `tests/test_docs.py`, `tests/test_log_config.py`, `tests/test_firewall.py` (now 158 tests total)
- `line_editor.py` — `LineEditorMixin` extracted from `scanner_ap.py` (readline, history, Tab-completion)
- `ap_cmd_handlers.py` — `APCommandHandlersMixin` extracted from `scanner_ap.py` (all interactive command handlers)
- `core/validators.py` — centralized input validation (interface, MAC, channel, IP range, SSID patterns)
- `mypy` type checking and `pip-audit` dependency audit added to CI
- `pytest-cov` coverage reporting with a regression floor (`--cov-fail-under`)
- `dependabot.yml` for automated weekly dependency updates
- Expanded `SECURITY.md` with threat model, supported versions table, and response timeline
- 82 new unit tests: validators, netops MTU/MSS helpers, command on/off parsing

### Changed
- Version reconciled to `1.0.0` across pyproject, banner, and CHANGELOG (was 0.1.0 / 9.4 / V8.2)
- `scanner_ap.py` refactored from 1413 → 668 LOC via mixin extraction
- `netops.py` reduced 1099 → 416 LOC; no file in `core/` now exceeds 500 LOC
- `validate_iface` deduplicated out of `scanner_ap.py` and `netops.py` into `core/validators.py`
- CI workflow now runs: ruff → mypy → pip-audit → pytest (with coverage)

### Security
- Bumped `pyinstaller` 5.13.0 → 6.22.3, clearing PYSEC-2023-292 and PYSEC-2026-1813
- Dependency vulnerability audit (`pip-audit`) now blocks CI on known CVEs

## [v0.9.4] — 2026-10-?

### Added
- APCC module: interactive AP control with hostapd + dnsmasq (radio, AP, DHCP, bridge, domain blocking)
- AP watchdog with exponential-backoff auto-reconnect on unexpected hostapd exit
- Policy-based routing for isolated AP subnet forwarding
- TCP MSS clamping (PMTU black-hole guard for cellular/VPN uplinks)
- Domain blocking and redirect via dnsmasq DNS sinkhole
- Client management: deauth, block, IP assignment, rate limiting, traffic timeout
- BLE advertisement spam module (Apple, Samsung, Microsoft, Google, FlipperZero)
- BLE chaos / delayed / single / spam modes
- WPA/WPA2 handshake capture with hc22000 export for hashcat
- WiFi attack module: deauth, auth DoS, Michael MIC DoS, probe flood, CSA, disassoc
- IR remote database explorer
- Dual-band channel-hopping scanner

### Security
- All interface names validated with `IFACE_REGEX` before use in subprocess calls
- All subprocess calls use list form (`shell=False`)
- Input validation added at `ScannerAP` entry point (`validate_iface`)
