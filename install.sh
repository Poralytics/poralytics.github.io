#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔══════════════════════════════════════╗"
echo "║   NEXUS Security Scanner v2.1.0     ║"
echo "║          Installation               ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}ERROR: Node.js not found. Install Node.js 18+ first.${NC}"
    exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}ERROR: Node.js 18+ required (found v$NODE_VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Node.js $(node -v) detected${NC}"

cd backend

# Install dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
npm install --silent
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Setup .env
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate random JWT secret
    JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    sed -i "s/change_me_to_random_32byte_hex_string/$JWT_SECRET/" .env
    echo -e "${GREEN}✓ .env created with random JWT_SECRET${NC}"
else
    echo -e "${YELLOW}ℹ .env already exists, skipping${NC}"
fi

# Initialize database
echo -e "\n${YELLOW}Initializing database...${NC}"
node init-db.js
echo -e "${GREEN}✓ Database initialized${NC}"

echo -e "\n${GREEN}╔══════════════════════════════════════╗"
echo "║        Installation Complete!        ║"
echo "╠══════════════════════════════════════╣"
echo "║  Start: cd backend && npm start      ║"
echo "║  Test:  cd backend && npm test       ║"
echo "║  URL:   http://localhost:3000        ║"
echo "║                                      ║"
echo "║  Admin: admin@nexus.local            ║"
echo "║  Pass:  Admin123!@#NexusChange       ║"
echo "║  ⚠️  CHANGE PASSWORD IMMEDIATELY!    ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"
