#!/usr/bin/env bash
# scripts/dev_up.sh — Start all HomeGuard services for development
# Usage: ./scripts/dev_up.sh [--no-sudo]

set -e
cd "$(dirname "$0")/.."

REPO_ROOT="$(pwd)"
export PYTHONPATH="$REPO_ROOT"

NO_SUDO=""
if [[ "$1" == "--no-sudo" ]]; then
    NO_SUDO="--no-sudo"
fi

# Check Redis
if ! redis-cli ping &>/dev/null; then
    echo "⚠ Redis not running. Starting..."
    brew services start redis
    sleep 1
fi
echo "✓ Redis OK"

# Ensure ~/.homeguard exists
mkdir -p ~/.homeguard

echo ""
echo "Starting HomeGuard services..."
echo ""

# Inventory (port 8006)
echo "→ inventory-service (port 8006)"
python -m services.inventory.main &
sleep 1

# Scanner (port 8001) — optionally with sudo
echo "→ scanner-service (port 8001)"
if [[ -z "$NO_SUDO" ]] && command -v sudo &>/dev/null; then
    sudo -E env "PYTHONPATH=$PYTHONPATH" python -m services.scanner.main &
else
    python -m services.scanner.main --no-sudo &
fi
sleep 1

# Discovery (port 8002)
echo "→ discovery-service (port 8002)"
python -m services.discovery.main &

# Identity (port 8003)
echo "→ identity-service (port 8003)"
python -m services.identity.main &

# Trust (port 8004)
echo "→ trust-service (port 8004)"
python -m services.trust.main &

# Notifier (port 8005)
echo "→ notifier-service (port 8005)"
python -m services.notifier.main &

sleep 1

# API Gateway (port 8000)
echo "→ api-gateway (port 8000)"
python -m services.api_gateway.main &

sleep 2

TOKEN=$(cat ~/.homeguard/token 2>/dev/null || echo "NOT GENERATED YET")
echo ""
echo "========================================="
echo "✓ HomeGuard running!"
echo "  Docs:  http://127.0.0.1:8000/docs"
echo "  Token: $TOKEN"
echo "========================================="
echo ""
echo "Press Ctrl+C to stop all services"

wait
