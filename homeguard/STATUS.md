12. Roadmap

Phase 0 — Foundation

 ✅ Repo scaffold, pyproject.toml, ruff/mypy/pytest config
 ✅ libs/common (config, schemas, events, bus, logging)
 ✅ Redis connectivity check, .env.example

Phase 1 — Inventory + Scanner (MVP core)

 ✅ inventory-service: models, migrations, CRUD API
 ✅ scanner-service: subnet detection, ARP sweep, ping-sweep fallback
 ✅ Event flow device.seen → inventory upsert → device.new
 ✅ api-gateway: /health, /scans, /devices, /network
 ✅ CLI: start, stop, status, scan, devices

Phase 2 — Identity

 ☐ OUI vendor lookup (bundled IEEE database)
 ☐ mDNS + SSDP + NetBIOS discovery
 ☐ Device-type classifier
 ☐ MAC-randomization detection and fingerprint merging

Phase 3 — Trust + Alerts

 ☐ trust-service rules engine with explainable reasons
 ☐ Port probing (allowlist) and risky-port rules
 ☐ notifier-service: alerts, macOS notifications
 ☐ /changes, /alerts, WebSocket /stream

Phase 4 — Polish

 ☐ Periodic quick scans while running, graceful session tracking
 ☐ Gateway MAC-change detection (ARP spoofing hint)
 ☐ OpenAPI cleanup, example client script, README with screenshots/asciinema
 ☐ Optional: DHCP fingerprint sniffing, menu-bar wrapper (rumps), React UI consuming the API

Current Status / Next Task

Status: Phase 0 + Phase 1 complete. All 11 tests pass.

Completed:
- Full repo scaffold matching Section 5 exactly
- libs/common: config, schemas, events, bus, logging
- inventory-service: SQLAlchemy 2.0 models, full repo layer (upsert/list/patch/alerts/scans/settings/changes), FastAPI HTTP API, Redis event subscriber
- scanner-service: macOS network detection (interface/subnet/gateway/SSID), ARP sweep via Scapy + ping-sweep fallback, device.seen publisher
- api-gateway: all Phase 1 public endpoints (/health, /scans, /devices, /network, /changes, /alerts, WebSocket /stream), token auth, CORS
- CLI: start/stop/status/scan/devices/changes with rich tables
- Stubs for discovery, identity, trust, notifier (Phase 2/3)
- Test suite: 11 passing unit + integration tests

Next task for the agent (Phase 2):

1. identity-service: download/bundle IEEE OUI CSV, implement oui.py lookup, classifier.py (device-type rules from vendor + mDNS hints), MAC-randomization detection, fingerprint.py (hash stable signals), subscribe to device.seen, publish device.identified.
2. discovery-service: zeroconf mDNS browser, SSDP socket listener, NetBIOS NBNS query, subscribe to device.seen, publish device.enriched.
3. Wire enrichment: inventory-service already handles device.enriched and device.identified events.
4. Tests: mock zeroconf/scapy, test OUI lookup, test classifier.

Update the checkboxes in Section 12 and this section after each milestone.
