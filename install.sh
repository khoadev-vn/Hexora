#!/usr/bin/env bash
# Hexora - Universal Security Engine Installer
# https://github.com/khoadev-vn/Hexora

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}"
echo "    __  __                          "
echo "   / / / /__  _  ______  _________ _"
echo "  / /_/ / _ \| |/_/ __ \/ ___/ __ \`/"
echo " / __  /  __/>  </ /_/ / /  / /_/ / "
echo "/_/ /_/\___/_/|_|\____/_/   \__,_/  "
echo -e "${NC}"
echo -e "${BOLD}Next-Generation Universal Security Engine${NC}"
echo "------------------------------------------------------"

# 1. Check Node.js
if ! command -v node >/dev/null 2>&1; then
  echo -e "${RED}❌ Error: Node.js (v18+) is required to run Hexora.${NC}"
  echo -e "${YELLOW}👉 Please install Node.js from: https://nodejs.org/${NC}"
  exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo -e "${YELLOW}⚠️ Warning: Node.js v18 or newer is recommended (detected $(node -v)).${NC}"
fi

# 2. Check npm
if ! command -v npm >/dev/null 2>&1; then
  echo -e "${RED}❌ Error: npm is required to install Hexora.${NC}"
  exit 1
fi

echo -e "${CYAN}⚡ Installing Hexora globally from GitHub (khoadev-vn/Hexora)...${NC}"
npm install -g khoadev-vn/Hexora

echo ""
echo -e "${GREEN}✅ Hexora has been successfully installed globally!${NC}"
echo "------------------------------------------------------"
echo -e "🚀 Run in any project directory:"
echo -e "   ${CYAN}hexora .${NC}         # Full security & secret audit"
echo -e "   ${CYAN}hexora watch${NC}     # Instant scan on every Ctrl+S"
echo -e "   ${CYAN}hexora init${NC}      # 1-Click setup for Cursor, Claude & VS Code"
echo -e "   ${CYAN}hexora bench${NC}     # Run adversarial verification benchmark"
echo ""
echo -e "🌟 GitHub: https://github.com/khoadev-vn/Hexora"
echo ""
