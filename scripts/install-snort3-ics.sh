#!/usr/bin/env bash
# TIDSOC Sensor Bootstrap Script
# Installs and configures Snort 3, PulledPork3, disables NIC offloading, and sets up Splunk UF and Suricata

set -euo pipefail

####### CONFIGURATION #######
INTERFACE="eth0"                # Network interface to monitor
HOME_NET="10.0.1.0/24"          # Update to your protected subnet
OINKCODE="YOUR_OINKCODE_HERE"   # Replace with your actual oinkcode
SPLUNK_INDEXER="10.0.1.10:9997" # Splunk UF target (host:port)
WAZUH_MANAGER="10.0.1.20"       # Wazuh Manager IP
SRC_DIR="$HOME/snort_src"

####### 1. SYSTEM UPDATE & DEPENDENCIES #######
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool python3-pip \
  google-perftools libgoogle-perftools-dev ragel libflatbuffers-dev libboost-all-dev libhyperscan-dev\
  net-tools curl jq

####### 2. DISABLE NIC OFFLOADING #######
cat <<EOF | sudo tee /etc/systemd/system/disable-offload.service
[Unit]
Description=Disable GRO/LRO Offloading
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

####### 3. BUILD & INSTALL SNORT 3 PREREQUISITES #######
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# SafeC (still needs to be built from source)
wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
tar -xzvf libsafec-02092020.tar.gz
cd libsafec-02092020.0-g6d921f
./configure && make && sudo make install
cd "$SRC_DIR"

# libdaq (latest, still needs to be built from source)
wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
tar -xzvf libdaq-3.0.5.tar.gz
cd libdaq-3.0.5
./bootstrap && ./configure && make && sudo make install
cd "$SRC_DIR"

sudo ldconfig

####### 4. BUILD & INSTALL SNORT 3 #######
wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
tar -xzvf snort3-3.1.17.0.tar.gz
cd snort3-3.1.17.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make && sudo make install

####### 5. SNORT CONFIGURATION #######
sudo mkdir -p /usr/local/etc/rules /usr/local/etc/so_rules /usr/local/etc/lists /var/log/snort
sudo touch /usr/local/etc/rules/local.rules /usr/local/etc/lists/default.blocklist
sudo groupadd -f snort
sudo useradd -r -s /sbin/nologin -c SNORT_IDS -g snort || true
sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

# Copy default config
sudo mkdir -p /etc/snort
sudo cp /usr/local/etc/snort/snort.lua /etc/snort/
sudo sed -i "s|HOME_NET = .*|HOME_NET = '$HOME_NET'|" /etc/snort/snort.lua

# Add a test ICMP rule
echo 'alert icmp any any -> any any (msg:"ICMP test"; sid:1000001; rev:1;)' | sudo tee /usr/local/etc/rules/local.rules

####### 6. INSTALL PULLEDPORK3 & CONFIGURE RULES #######
cd "$SRC_DIR"
git clone https://github.com/shirkdog/pulledpork3.git
sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
sudo cp pulledpork3/etc/pulledpork.conf /usr/local/etc/pulledpork3/
sudo sed -i "s|oinkcode =.*|oinkcode = $OINKCODE|" /usr/local/etc/pulledpork3/pulledpork.conf
sudo sed -i "s|snort_path =.*|snort_path = /usr/local/bin/snort|" /usr/local/etc/pulledpork3/pulledpork.conf
sudo sed -i "s|local_rules =.*|local_rules = /usr/local/etc/rules/local.rules|" /usr/local/etc/pulledpork3/pulledpork.conf

# Run PulledPork3 for the first time
sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf

####### 7. FINAL SNORT CONFIG (JSON LOGGING) #######
sudo tee /etc/snort/snort.lua <<EOF
HOME_NET = '$HOME_NET'
EXTERNAL_NET = 'any'
RULE_PATH = '/usr/local/etc/rules'
SO_RULE_PATH = '/usr/local/etc/so_rules'
LISTS_PATH = '/usr/local/etc/lists'

ips = {
    rules = [[ include \$RULE_PATH/pulledpork.rules ]]
}

alert_json = {
    file = true,
