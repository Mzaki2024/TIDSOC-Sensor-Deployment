#!/usr/bin/env bash
# Install-Snort3-Fresh: Fresh Snort 3 installation with systemd services
set -euo pipefail

####### CONFIGURATION #######
INTERFACE="eth0"                # Network interface to monitor
HOME_NET="10.0.1.0/24"          # Protected network
OINKCODE="5c0634a44e8b91a23e66c280f2cf69a8bef39513"   # Snort.org oinkcode
SRC_DIR="$HOME/snort_src"       # Source/build directory

####### 1. SYSTEM PREPARATION #######
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool python3-pip \
  google-perftools libgoogle-perftools-dev ragel libflatbuffers-dev libboost-all-dev libhyperscan-dev \
  net-tools curl jq

####### 2. NIC OPTIMIZATION #######
cat <<EOF | sudo tee /etc/systemd/system/disable-offload.service
[Unit]
Description=Disable NIC Offloading
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ethtool -K $INTERFACE gro off
ExecStart=/sbin/ethtool -K $INTERFACE lro off

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now disable-offload.service

####### 3. COMPILE & INSTALL #######
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
cd ../../

sudo ldconfig

####### 4. CONFIGURATION #######
# User/group setup
sudo groupadd snort
sudo useradd -r -s /sbin/nologin -c SNORT_IDS -g snort snort

# Directory structure
sudo mkdir -p /etc/snort /var/log/snort /usr/local/etc/{rules,so_rules,lists}
sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

# Base config
sudo cp /usr/local/etc/snort/snort.lua /etc/snort/
sudo sed -i "s|HOME_NET = .*|HOME_NET = '$HOME_NET'|" /etc/snort/snort.lua

# Test rule
echo 'alert icmp any any -> any any (msg:"ICMP test"; sid:1000001; rev:1;)' | sudo tee /usr/local/etc/rules/local>


####### 5. SYSTEMD SERVICE SETUP #######
# Snort service
sudo tee /etc/systemd/system/snort3.service > /dev/null <<EOF
[Unit]
Description=Snort 3 Network IDS/IPS
After=network.target disable-offload.service

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /etc/snort/snort.lua -i $INTERFACE -s 65535 -k none -l /var/log/snort -D -u sno>
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# PulledPork service
sudo tee /etc/systemd/system/pulledpork3.service > /dev/null <<EOF
[Unit]
Description=PulledPork3 Rule Management
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
ExecStartPost=/bin/systemctl restart snort3
EOF

# PulledPork timer
sudo tee /etc/systemd/system/pulledpork3.timer > /dev/null <<EOF
[Unit]
Description=Daily PulledPork3 Rule Updates

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

####### 6. PULLEDPORK3 SETUP #######
cd "$SRC_DIR"
git clone https://github.com/shirkdog/pulledpork3.git
sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/

# Config file
sudo tee /usr/local/etc/pulledpork3/pulledpork.conf > /dev/null <<EOF
oinkcode=$OINKCODE
snort_path=/usr/local/bin/snort
local_rules=/usr/local/etc/rules/local.rules
rule_path=/usr/local/etc/rules/pulledpork.rules
rule_url=https://www.snort.org/rules/snortrules-snapshot-29120.tar.gz|$OINKCODE|snortrules-snapshot-29120.tar.gz
EOF

# Initial rules download
sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf

####### 7. ENABLE SERVICES #######
sudo systemctl daemon-reload
sudo systemctl enable --now snort3
sudo systemctl enable --now pulledpork3.timer

####### 8. FINAL CONFIG #######
sudo tee -a /etc/snort/snort.lua <<EOF

alert_json = {
    file = true,
    limit = 100,
    filename = '/var/log/snort/alert_json.txt'
}
EOF

echo "Fresh Snort 3 installation complete with systemd services!"