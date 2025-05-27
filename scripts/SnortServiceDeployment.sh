!/usr/bin/env bash
# TIDSOC Sensor Deployment Script (All-in-One)
set -euo pipefail

####### CONFIGURATION #######
INTERFACE="eth0"                # Monitoring interface
HOME_NET="10.0.1.0/24"          # Protected network
OINKCODE="YOUR_OINKCODE_HERE"   # Snort.org oinkcode
SRC_DIR="$HOME/snort_src"       # Source/build directory

####### FUNCTIONS #######
component_installed() { [ -e "$1" ]; }

####### 1. SYSTEM PREP #######
sudo apt-get update
sudo apt-get install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool python3-pip \
  google-perftools libgoogle-perftools-dev ragel libflatbuffers-dev libboost-all-dev libhyperscan-dev \
  net-tools curl jq

####### 2. NIC OPTIMIZATION SERVICE #######
if ! component_installed "/etc/systemd/system/snort3-nic.service"; then
  sudo tee /etc/systemd/system/snort3-nic.service > /dev/null <<EOF
[Unit]
Description=Set NIC for Snort3 (Promiscuous + No GRO/LRO)
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
fi

####### 3. BUILD & INSTALL SNORT 3 #######
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# SafeC
if ! component_installed "/usr/local/lib/libsafec.so"; then
  wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
  tar -xzf libsafec-02092020.tar.gz
  cd libsafec-02092020.0-g6d921f
  ./configure && make && sudo make install
  cd ..
fi

# libDAQ
if ! component_installed "/usr/local/lib/libdaq.so"; then
  wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
  tar -xzf libdaq-3.0.5.tar.gz
  cd libdaq-3.0.5
  ./bootstrap && ./configure && make && sudo make install
  cd ..
fi

# Snort 3 Core
if ! component_installed "/usr/local/bin/snort"; then
  wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
  tar -xzf snort3-3.1.17.0.tar.gz
  cd snort3-3.1.17.0
  ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
  cd build
  make && sudo make install
  cd ../..
fi
sudo ldconfig

####### 4. SNORT CONFIGURATION #######
sudo mkdir -p /etc/snort /var/log/snort
sudo cp /usr/local/etc/snort/*.lua /etc/snort/
sudo sed -i "s|HOME_NET = .*|HOME_NET = '$HOME_NET'|" /etc/snort/snort.lua

# Create Snort user/group
sudo groupadd -f snort
if ! id snort >/dev/null 2>&1; then
  sudo useradd -r -s /sbin/nologin -c SNORT_IDS -g snort
fi

sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

# Test rule
echo 'alert icmp any any -> any any (msg:"ICMP test"; sid:1000001; rev:1;)' | sudo tee /usr/local/etc/rules/local.rules

####### 5. SNORT SYSTEMD SERVICE #######
if ! component_installed "/etc/systemd/system/snort3.service"; then
  sudo tee /etc/systemd/system/snort3.service > /dev/null <<EOF
[Unit]
Description=Snort3 IDS/IPS Service
After=snort3-nic.service

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /etc/snort/snort.lua -i $INTERFACE -s 65535 -k none -l /var/log/snort -D -u snort -g snort -->
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now snort3
fi

####### 6. PULLEDPORK3 SETUP #######
cd "$SRC_DIR"
if ! component_installed "/usr/local/bin/pulledpork3/pulledpork.py"; then
  git clone https://github.com/shirkdog/pulledpork3.git
  sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
  sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
  sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
  sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
  
  sudo tee /usr/local/etc/pulledpork3/pulledpork.conf > /dev/null <<EOF
oinkcode=$OINKCODE
snort_path=/usr/local/bin/snort
local_rules=/usr/local/etc/rules/local.rules
rule_path=/usr/local/etc/rules/pulledpork.rules
rule_url=https://www.snort.org/rules/snortrules-snapshot-29120.tar.gz|$OINKCODE|snortrules-snapshot-29120.tar.gz
EOF
fi

####### 7. PULLEDPORK3 AUTOMATION #######
if ! component_installed "/etc/systemd/system/pulledpork3.timer"; then
  sudo tee /etc/systemd/system/pulledpork3.service > /dev/null <<EOF
[Unit]
Description=PulledPork3 Rule Updater

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
ExecStartPost=/bin/systemctl restart snort3
EOF

  sudo tee /etc/systemd/system/pulledpork3.timer > /dev/null <<EOF
[Unit]
Description=Daily PulledPork3 Rule Update

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now pulledpork3.timer
fi

####### 8. FINAL CHECKS #######
sudo snort -T -c /etc/snort/snort.lua
echo "TIDSOC sensor deployment complete!"
