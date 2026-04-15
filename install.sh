#!/bin/bash
# NetWatch Enterprise SIEM/IDS/IPS Installation Script
# Production-ready deployment automation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NETWATCH_USER="netwatch"
NETWATCH_GROUP="netwatch"
INSTALL_DIR="/opt/netwatch"
CONFIG_DIR="/etc/netwatch"
LOG_DIR="/var/log/netwatch"
DATA_DIR="/var/lib/netwatch"
RULES_DIR="/etc/netwatch/rules"
PLAYBOOKS_DIR="/etc/netwatch/playbooks"

echo -e "${BLUE}🚀 NetWatch Enterprise SIEM/IDS/IPS Installation${NC}"
echo "=================================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root${NC}"
   exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}❌ Python 3.8+ required, found $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python version check passed${NC}"

# Install system dependencies
echo -e "${YELLOW}📦 Installing system dependencies...${NC}"
apt-get update
apt-get install -y \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libpcap-dev \
    tcpdump \
    iptables \
    nftables \
    systemd \
    curl \
    wget \
    git

# Create user and directories
echo -e "${YELLOW}👤 Creating NetWatch user and directories...${NC}"
useradd -r -s /bin/false -d "$INSTALL_DIR" "$NETWATCH_USER" 2>/dev/null || true

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$RULES_DIR" "$PLAYBOOKS_DIR"
chown -R "$NETWATCH_USER:$NETWATCH_GROUP" "$INSTALL_DIR" "$LOG_DIR" "$DATA_DIR"

# Install Python dependencies
echo -e "${YELLOW}🐍 Installing Python dependencies...${NC}"
cd "$(dirname "$0")"
pip3 install -r requirements.txt

# Install NetWatch
echo -e "${YELLOW}📥 Installing NetWatch...${NC}"
pip3 install -e .

# Copy configuration files
echo -e "${YELLOW}⚙️ Setting up configuration...${NC}"

# Create default configuration
cat > "$CONFIG_DIR/config.yaml" << 'EOF'
agent:
  name: netwatch-01
  environment: production
  dry_run: false

logging:
  level: INFO
  file: /var/log/netwatch/agent.log
  max_bytes: 10485760
  backup_count: 5

collectors:
  filetail:
    enabled: true
    files: ['/var/log/auth.log', '/var/log/syslog']
  syslog:
    enabled: true
    host: 0.0.0.0
    port: 514
  suricata:
    enabled: false
    eve_path: /var/log/suricata/eve.json
  netflow:
    enabled: false
    port: 2055
  scapy:
    enabled: true
    interface: any

rules:
  path: /etc/netwatch/rules/
  reload_interval: 300

storage:
  type: sqlite
  path: /var/lib/netwatch/netwatch.db

api:
  enabled: true
  host: 127.0.0.1
  port: 8080

response:
  enabled: true
  dry_run: false
  playbooks_path: /etc/netwatch/playbooks/
EOF

# Copy example rules
cp netwatch/rules/examples/*.yaml "$RULES_DIR/" 2>/dev/null || true

# Create example playbook
cat > "$PLAYBOOKS_DIR/block_src_ip.yaml" << 'EOF'
name: block-src-ip
description: Block source IP address
steps:
  - action: block_ip
    args:
      ip: "{src_ip}"
      timeout: 3600
  - action: notify
    args:
      channel: log
      message: "Blocked IP {src_ip} for {timeout} seconds"
EOF

# Set permissions
chown -R "$NETWATCH_USER:$NETWATCH_GROUP" "$CONFIG_DIR" "$RULES_DIR" "$PLAYBOOKS_DIR"
chmod 755 "$CONFIG_DIR" "$RULES_DIR" "$PLAYBOOKS_DIR"

# Install systemd service
echo -e "${YELLOW}🔧 Installing systemd service...${NC}"
cp netwatch.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable netwatch

# Set capabilities for packet capture
echo -e "${YELLOW}🔐 Setting up capabilities...${NC}"
PYTHON_PATH=$(which python3)
setcap cap_net_raw,cap_net_admin+ep "$PYTHON_PATH" 2>/dev/null || {
    echo -e "${YELLOW}⚠️ Could not set capabilities. NetWatch will need to run as root for packet capture.${NC}"
}

# Create logrotate configuration
echo -e "${YELLOW}📝 Setting up log rotation...${NC}"
cat > /etc/logrotate.d/netwatch << 'EOF'
/var/log/netwatch/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 netwatch netwatch
    postrotate
        systemctl reload netwatch > /dev/null 2>&1 || true
    endscript
}
EOF

# Initialize database
echo -e "${YELLOW}🗄️ Initializing database...${NC}"
sudo -u "$NETWATCH_USER" python3 -c "
from netwatch.storage.db import init_db
init_db('sqlite:///$DATA_DIR/netwatch.db')
print('Database initialized successfully')
"

# Test installation
echo -e "${YELLOW}🧪 Testing installation...${NC}"
if python3 -c "import netwatch; print('NetWatch import successful')" 2>/dev/null; then
    echo -e "${GREEN}✅ NetWatch installation test passed${NC}"
else
    echo -e "${RED}❌ NetWatch installation test failed${NC}"
    exit 1
fi

# Create CLI symlink
ln -sf "$INSTALL_DIR/bin/netwatchctl" /usr/local/bin/netwatchctl 2>/dev/null || true

echo ""
echo -e "${GREEN}🎉 NetWatch installation completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "1. Review configuration: $CONFIG_DIR/config.yaml"
echo "2. Add custom rules to: $RULES_DIR/"
echo "3. Start NetWatch: systemctl start netwatch"
echo "4. Check status: systemctl status netwatch"
echo "5. View logs: journalctl -u netwatch -f"
echo ""
echo -e "${BLUE}🛠️ Management Commands:${NC}"
echo "• netwatchctl alerts          # List alerts"
echo "• netwatchctl block-ip IP     # Block IP address"
echo "• netwatchctl stats           # Show statistics"
echo "• netwatchctl test-rule FILE  # Test rule"
echo ""
echo -e "${BLUE}📚 Documentation:${NC}"
echo "• README.md                   # Complete documentation"
echo "• /etc/netwatch/rules/        # Example rules"
echo "• /etc/netwatch/playbooks/    # Response playbooks"
echo ""
echo -e "${GREEN}🚀 NetWatch is ready for production deployment!${NC}"

