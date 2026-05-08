#!/usr/bin/env bash
# install.sh — one-shot installer for bugbounty-AI / venomeye
#
# Sets up:
#   1. Python virtualenv (.venv) + pip dependencies (requirements.txt)
#   2. All Go-based recon tools (subfinder, dnsx, httpx, ...)
#   3. System packages (nmap, sqlmap, weasyprint deps)
#   4. testssl.sh (cloned to /opt/testssl, symlinked into /usr/local/bin)
#   5. Optional: js-beautify (npm), nuclei templates update
#
# Tested on Kali Linux / Debian. Re-running is safe — every step is idempotent.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }

have()  { command -v "$1" >/dev/null 2>&1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# 1. Python virtualenv + pip deps
# ---------------------------------------------------------------------------
info "Setting up Python virtual environment (.venv)"
if ! have python3; then
    err "python3 is required but not found"; exit 1
fi
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
info "Python deps installed into $(pwd)/.venv"

# ---------------------------------------------------------------------------
# 2. System packages (apt)
# ---------------------------------------------------------------------------
if have apt-get; then
    info "Installing system packages via apt"
    sudo apt-get update -qq
    sudo apt-get install -y \
        nmap sqlmap curl git \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
        libcairo2 libgdk-pixbuf-2.0-0 libffi-dev
else
    warn "apt-get not found — install nmap, sqlmap, curl manually"
fi

# ---------------------------------------------------------------------------
# 3. Go-based tools
# ---------------------------------------------------------------------------
if ! have go; then
    warn "Go is not installed. Installing golang-go via apt..."
    sudo apt-get install -y golang-go
fi

# Make sure $GOPATH/bin is on PATH for the rest of this script
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/owasp-amass/amass/v4/...@master"
)

for pkg in "${GO_TOOLS[@]}"; do
    bin="$(basename "${pkg%@*}")"
    if have "$bin"; then
        info "  $bin already installed — skipping"
    else
        info "  installing $bin"
        go install -v "$pkg" || warn "    failed to install $pkg"
    fi
done

# ---------------------------------------------------------------------------
# 4. testssl.sh
# ---------------------------------------------------------------------------
if ! have testssl.sh; then
    info "Installing testssl.sh into /opt/testssl"
    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
    sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
else
    info "testssl.sh already installed — skipping"
fi

# ---------------------------------------------------------------------------
# 5. Optional: js-beautify (used by js_analyzer.py)
# ---------------------------------------------------------------------------
if have npm; then
    if ! have js-beautify; then
        info "Installing js-beautify (npm, optional)"
        sudo npm install -g js-beautify || warn "  npm install failed"
    fi
else
    warn "npm not found — js-beautify (optional) not installed"
fi

# ---------------------------------------------------------------------------
# 6. nuclei templates
# ---------------------------------------------------------------------------
if have nuclei; then
    info "Updating nuclei templates"
    nuclei -update-templates -silent || true
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo
info "Installation complete."
echo
echo "Next steps:"
echo "  source .venv/bin/activate"
echo "  python3 venomeye.py -d target.com -o ./output/"
echo
warn "If any go-installed binary is 'not found', add \$GOPATH/bin to your PATH:"
echo "  echo 'export PATH=\"\$PATH:\$HOME/go/bin\"' >> ~/.zshrc && source ~/.zshrc"
