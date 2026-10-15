# HomeGuard README

## What is it?
HomeGuard is a home-network security tool that discovers every device on your local Wi-Fi, identifies each by vendor and type, assigns a trust score, and flags anything new — like a doorbell for your network.

## Quick Start

### Prerequisites
- Python 3.11+
- Redis (`brew install redis && brew services start redis`)
- For ARP scanning: sudo access

### Install dependencies
```bash
cd homeguard
pip install -e ".[dev]"
```

### Start HomeGuard
```bash
python -m cli.homeguard start

# Or without sudo (uses ping sweep instead of ARP):
python -m cli.homeguard start --no-sudo
```

### Scan for devices
```bash
python -m cli.homeguard scan
python -m cli.homeguard devices
```

### See what changed since last session
```bash
python -m cli.homeguard changes
```

### Stop HomeGuard
```bash
python -m cli.homeguard stop
```

## API
- Docs: http://127.0.0.1:8000/docs
- Auth: `X-HomeGuard-Token: <token from ~/.homeguard/token>`

### Key endpoints
```bash
TOKEN=$(cat ~/.homeguard/token)

# Start a scan
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "X-HomeGuard-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"quick"}'

# List devices
curl http://127.0.0.1:8000/api/v1/devices \
  -H "X-HomeGuard-Token: $TOKEN"

# Label a device as trusted
curl -X PATCH http://127.0.0.1:8000/api/v1/devices/<id> \
  -H "X-HomeGuard-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_label":"Dad'\''s Phone","status":"trusted"}'

# What changed since last session?
curl "http://127.0.0.1:8000/api/v1/changes?since=2026-10-22T20:00:00Z" \
  -H "X-HomeGuard-Token: $TOKEN"

# Live WebSocket stream
wscat -c "ws://127.0.0.1:8000/api/v1/stream?token=$TOKEN"
```

## Architecture

```
UI / curl → api-gateway (:8000) → internal services via HTTP + Redis pub/sub
                                 ├─ scanner (:8001)    ARP/ping sweep
                                 ├─ discovery (:8002)  mDNS/SSDP (Phase 2)
                                 ├─ identity (:8003)   OUI/fingerprint (Phase 2)
                                 ├─ trust (:8004)      score rules (Phase 3)
                                 ├─ notifier (:8005)   macOS alerts (Phase 3)
                                 └─ inventory (:8006)  SQLite database
```

## Running Tests
```bash
pytest tests/ -v
```

## macOS Notes
- On first run: allow **Local Network** access when macOS prompts your terminal
- ARP scanning needs sudo. Use `--no-sudo` for a privilege-free ping sweep
- Docker cannot see the LAN — all services run natively
