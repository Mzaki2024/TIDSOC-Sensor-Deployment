#!/usr/bin/env bash
# Install-Snort3-Fresh.sh: Fresh Snort 3 install with systemd services and full config
set -euo pipefail

####### CONFIGURATION #######
INTERFACE="eth0"
HOME_NET="10.0.1.0/24"
OINKCODE="YOUR_OINKCODE_HERE"
SRC_DIR="$HOME/snort_src"

####### 1. SYSTEM PREP #######
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool python3-pip \
  google-perftools libgoogle-perftools-dev ragel libflatbuffers-dev libboost-all-dev libhyperscan-dev \
  net-tools curl jq

####### 2. NIC OPTIMIZATION SERVICE #######
sudo tee /etc/systemd/system/snort3-nic.service > /dev/null <<EOF
[Unit]
Description=Set Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev $INTERFACE promisc on
ExecStart=/usr/sbin/ethtool -K $INTERFACE gro off lro off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now snort3-nic.service

####### 3. BUILD & INSTALL SNORT 3 #######
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# SafeC
wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
tar -xzvf libsafec-02092020.tar.gz
cd libsafec-02092020.0-g6d921f
./configure && make && sudo make install
cd ..

# libDAQ
wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
tar -xzvf libdaq-3.0.5.tar.gz
cd libdaq-3.0.5
./bootstrap && ./configure && make && sudo make install
cd ..

# Snort 3 Core
wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
tar -xzvf snort3-3.1.17.0.tar.gz
cd snort3-3.1.17.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make && sudo make install
cd ../..

sudo ldconfig

####### 4. SNORT CONFIGURATION #######
sudo groupadd snort || true
sudo useradd -r -s /sbin/nologin -c SNORT_IDS -g snort snort || true
sudo mkdir -p /etc/snort /var/log/snort /usr/local/etc/snort/rules /usr/local/etc/snort/so_rules /usr/local/etc/snort/lists
sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

# Copy all Lua config files
sudo cp /usr/local/etc/snort/*.lua /etc/snort/

# Download community rules
sudo mkdir -p /usr/local/etc/snort/rules/snort3-community-rules
wget -qO- https://www.snort.org/downloads/community/snort3-community-rules.tar.gz | sudo tar xz -C /usr/local/etc/snort/rules/snort3-community-rules/

# Add a test local rule
echo 'alert icmp any any -> any any (msg:"ICMP test"; sid:1000001; rev:1;)' | sudo tee /usr/local/etc/snort/rules/local.rules

# Write snort.lua with best practices, Hyperscan, and IPS enabled
sudo tee /etc/snort/snort.lua > /dev/null <<EOF
-- Snort 3 configuration (with structured JSON logging)
dofile('/etc/snort/snort_defaults.lua')

HOME_NET = '$HOME_NET'
EXTERNAL_NET = '!"$HOME_NET"'

search_engine = { search_method = "hyperscan" }
detection = { hyperscan_literals = true, pcre_to_regex = true }

ips = {
    enable_builtin_rules = true,
    variables = default_variables,
    rules = [[
        include /usr/local/etc/snort/rules/local.rules
        include /usr/local/etc/snort/rules/snort3-community-rules/snort3-community.rules
        include /usr/local/etc/snort/rules/pulledpork.rules
    ]]
}

alert_json = {
    file = true,
    limit = 100,
    filename = '/var/log/snort/alert_json.txt',
    fields = 'timestamp seconds action class b64_data dir dst_addr dst_ap dst_port eth_dst eth_len eth_src eth_type gid icmp_code icmp_id icmp_seq icmp_type iface ip_id ip_len msg mpls pkt_gen pkt_len pkt_num priority proto rev rule service sid src_addr src_ap src_port target tcp_ack tcp_flags tcp_len tcp_seq tcp_win tos ttl udp_len vlan'
}

logdir = '/var/log/snort'
EOF

####### 5. SNORT SYSTEMD SERVICE #######
sudo tee /etc/systemd/system/snort3.service > /dev/null <<EOF
[Unit]
Description=Snort 3 Network IDS/IPS
After=network.target snort3-nic.service

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /etc/snort/snort.lua -i $INTERFACE -s 65535 -k none -l /var/log/snort -D -u snort -g snort --create-pidfile --plugin-path /usr/local/lib/snort_extra
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now snort3

####### 6. PULLEDPORK3 SERVICE & TIMER #######
cd "$SRC_DIR"
git clone https://github.com/shirkdog/pulledpork3.git
sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
sudo tee /usr/local/etc/pulledpork3/pulledpork.conf > /dev/null <<EOF
oinkcode=$OINKCODE
snort_path=/usr/local/bin/snort
local_rules=/usr/local/etc/snort/rules/local.rules
rule_path=/usr/local/etc/snort/rules/pulledpork.rules
rule_url=https://www.snort.org/rules/snortrules-snapshot-29120.tar.gz|$OINKCODE|snortrules-snapshot-29120.tar.gz
EOF

# Initial rules download
sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf

# PulledPork3 service
sudo tee /etc/systemd/system/pulledpork3.service > /dev/null <<EOF
[Unit]
Description=PulledPork3 Rule Management
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
ExecStartPost=/bin/systemctl restart snort3
EOF

# PulledPork3 timer
sudo tee /etc/systemd/system/pulledpork3.timer > /dev/null <<EOF
[Unit]
Description=Daily PulledPork3 Rule Updates

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now pulledpork3.timer

echo "Fresh Snort 3 installation complete with full configuration, Hyperscan, IPS, and automated rule updates!"
