#!/usr/bin/env bash
# ============================================================
#  ATP SDK — Auto-install for SCHOOL SERVER (Linux/macOS)
#  Nessuna configurazione di rete necessaria.
# ============================================================
set -e
echo
echo "  🏫  ATP School Server — Installazione Linux/macOS"
echo "  =================================================="
echo

if ! command -v python3 &>/dev/null; then
    echo "  ❌ Python3 non trovato. Installa con: sudo apt install python3 python3-pip"
    exit 1
fi
echo "  ✅ Python3: $(python3 --version)"

ATP_DIR="$HOME/atp-school-server"
mkdir -p "$ATP_DIR"
cd "$ATP_DIR"

echo
echo "  📦 Download ATP protocol..."
if [ -d "ATP" ]; then
    cd ATP && git pull 2>/dev/null || true; cd ..
else
    git clone https://github.com/nousresearch/atp.git ATP 2>/dev/null || {
        echo "  📋 Copia i file ATP in $ATP_DIR/ATP/"; mkdir -p ATP
    }
fi

echo
echo "  📦 Installazione dipendenze..."
pip3 install aiohttp blake3 cbor2 cryptography pyngrok 2>&1 | grep -v "already satisfied" || true

echo
echo "  ✅ Installazione completata!"
echo
echo "  Per avviare il server (ascolta su localhost, pronta all'uso):"
echo "    cd $ATP_DIR/ATP/sdk/examples"
echo "    python3 school_server.py"
echo
