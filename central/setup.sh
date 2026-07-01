#!/bin/bash
# ============================================================
#  Blueteam Monitor - Quick Setup Script
#  Jalankan dari folder: blueteam-monitor/central/
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ██████╗ ██╗     ██╗   ██╗███████╗████████╗███████╗ █████╗ ███╗   ███╗"
echo "  ██╔══██╗██║     ██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"
echo "  ██████╔╝██║     ██║   ██║█████╗     ██║   █████╗  ███████║██╔████╔██║"
echo "  ██╔══██╗██║     ██║   ██║██╔══╝     ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
echo "  ██████╔╝███████╗╚██████╔╝███████╗   ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
echo "  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}"
echo "  Blueteam AI/ML Log Monitor - Phase 1 Setup"
echo "  ============================================"
echo ""

# Cek Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERROR] Docker tidak ditemukan. Install Docker dulu.${NC}"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo -e "${RED}[ERROR] Docker Compose tidak ditemukan.${NC}"
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Docker tersedia"

# Buat .env jika belum ada
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}[INFO]${NC} File .env dibuat dari .env.example"
    echo -e "${YELLOW}[INFO]${NC} Edit .env untuk mengisi Telegram/Discord token (opsional)"
fi

# Pull images
echo ""
echo -e "[1/4] Pulling Docker images..."
docker compose pull --quiet

# Build ML engine
echo -e "[2/4] Building ML Engine..."
docker compose build ml-engine --quiet

# Start semua service
echo -e "[3/4] Starting services..."
docker compose up -d

# Tunggu sebentar
echo -e "[4/4] Waiting for services to be ready..."
sleep 10

# Cek status
echo ""
echo "Status services:"
docker compose ps

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Setup selesai!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  📊 Grafana Dashboard : http://localhost:3000"
echo "     Username          : admin"
echo "     Password          : blueteam_grafana"
echo ""
echo "  📡 Fluent Bit        : http://localhost:2020"
echo "  🗄️  PostgreSQL        : localhost:5432"
echo "  🔴 Redis             : localhost:6379"
echo ""
echo "  Log receiver ports:"
echo "  - Syslog TCP/UDP  : 5140"
echo "  - Agent Forward   : 5170"
echo ""
echo -e "${YELLOW}  Langkah selanjutnya:${NC}"
echo "  1. Deploy agent ke mesin target (lihat ../agent/)"
echo "  2. Isi Telegram/Discord token di .env jika diinginkan"
echo "  3. Restart: docker compose restart ml-engine"
echo ""
