#!/bin/bash

# Web3CRIT Scanner - Quick Install Script
# This script installs the scanner globally on your system

set -e

echo ""
echo "================================================================"
echo "          WEB3CRIT Scanner - Installation Script"
echo "================================================================"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js is not installed"
    echo "Please install Node.js (>= 14.0.0) from https://nodejs.org/"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 14 ]; then
    echo "[ERROR] Node.js version must be >= 14.0.0"
    echo "Current version: $(node -v)"
    echo "Please upgrade Node.js from https://nodejs.org/"
    exit 1
fi

echo "[OK] Node.js $(node -v) detected"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "[ERROR] npm is not installed"
    exit 1
fi

echo "[OK] npm $(npm -v) detected"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "[INFO] Installing dependencies..."
cd "$SCRIPT_DIR"
npm install --quiet

echo "[INFO] Installing web3crit globally..."
npm uninstall -g web3crit-scanner 2>/dev/null || true

# Pack and install to avoid symlink issues
echo "[INFO] Creating package..."
npm pack --quiet

# Get the package filename
PACKAGE_FILE=$(ls web3crit-scanner-*.tgz 2>/dev/null | head -1)

if [ -n "$PACKAGE_FILE" ]; then
    echo "[INFO] Installing from package: $PACKAGE_FILE"
    npm install -g "$PACKAGE_FILE" --quiet
    rm -f "$PACKAGE_FILE"
else
    # Fallback to direct install
    npm install -g . --quiet
fi

echo ""
echo "================================================================"
echo "            Installation Complete!"
echo "================================================================"
echo ""
echo "You can now use the 'web3crit' command from anywhere:"
echo ""
echo "  web3crit scan <file.sol>           # Scan a single contract"
echo "  web3crit scan <directory>          # Scan all contracts in directory"
echo "  web3crit scan --format json        # Output as JSON"
echo "  web3crit --help                    # Show all options"
echo ""
echo "Example:"
echo "  web3crit scan contracts/MyToken.sol"
echo ""

# Verify installation
if command -v web3crit &> /dev/null; then
    echo "Installation verified: $(which web3crit)"
    echo "Version: $(web3crit --version)"
else
    echo "[WARNING] 'web3crit' command not found in PATH"
    echo "You may need to add npm global bin directory to your PATH"
    echo ""
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$PATH:$(npm config get prefix)/bin\""
fi

echo ""
