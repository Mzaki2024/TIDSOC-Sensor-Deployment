#!/usr/bin/env bash
# TIDSOC Sensor Bootstrap Script (Idempotent)
set -euo pipefail

####### CONFIGURATION #######
INTERFACE="eth0"                # Network interface to monitor
HOME_NET="10.0.1.0/24"          # Update to your protected subnet
OINKCODE="5c0634a44e8b91a23e66c280f2cf69a8bef39513"   # Replace with your actual oinkcode
SPLUNK_INDEXER="10.0.1.10:9997" # Splunk UF target (host:port)
WAZUH_MANAGER="10.0.1.20"       # Wazuh Manager IP
SRC_DIR="$HOME/snort_src"

####### FUNCTIONS #######
component_installed() {
    [ -e "$1" ]
}

####### 1. SYSTEM UPDATE & DEPENDENCIES #######
# Check for gperftools as proxy for full dependency install
if ! component_installed "/usr/lib/x86_64-linux-gnu/libtcmalloc.so"; then
    sudo apt-get update && sudo apt-get upgrade -y
    sudo apt-get install -y \
      build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
      libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
      openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
      autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
      libunwind-dev libmnl-dev ethtool python3-pip \
      google-perftools libgoogle-perftools-dev ragel libflatbuffers-dev libboost-all-dev libhyperscan-dev\
      net-tools curl jq
fi

####### 2. DISABLE NIC OFFLOADING #######
if ! component_installed "/etc/systemd/system/disable-offload.service"; then
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
fi

####### 3. BUILD & INSTALL SNORT 3 PREREQUISITES #######
mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# SafeC
if ! component_installed "/usr/local/lib/libsafec.so"; then
    wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
    tar -xzvf libsafec-02092020.tar.gz
    cd libsafec-02092020.0-g6d921f
    ./configure && make && sudo make install
    cd "$SRC_DIR"
fi

# libdaq
if ! component_installed "/usr/local/lib/libdaq.so"; then
    wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
    tar -xzvf libdaq-3.0.5.tar.gz
    cd libdaq-3.0.5
    ./bootstrap && ./configure && make && sudo make install
    cd "$SRC_DIR"
fi

sudo ldconfig

####### 4. BUILD & INSTALL SNORT 3 #######
if ! component_installed "/usr/local/bin/snort"; then
    wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
    tar -xzvf snort3-3.1.17.0.tar.gz
    cd snort3-3.1.17.0
    ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
    cd build
    make && sudo make install
fi

####### 5. SNORT CONFIGURATION #######
sudo mkdir -p /usr/local/etc/rules /usr/local/etc/so_rules /usr/local/etc/lists /var/log/snort

# Create snort group if missing
if ! getent group snort >/dev/null; then
    sudo groupadd -f snort
fi

# Create snort user if missing
if ! id snort >/dev/null 2>&1; then
    sudo useradd -r -s /sbin/nologin -c SNORT_IDS -g snort
fi

sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

# Only copy config if missing
if ! component_installed "/etc/snort/snort.lua"; then
    sudo mkdir -p /etc/snort
    sudo cp /usr/local/etc/snort/*.lua /etc/snort/
    sudo sed -i "s|HOME_NET = .*|HOME_NET = '$HOME_NET'|" /etc/snort/snort.lua
fi

# Add test rule if missing
if ! component_installed "/usr/local/etc/rules/local.rules"; then
    echo 'alert icmp any any -> any any (msg:"ICMP test"; sid:1000001; rev:1;)' | sudo tee /usr/local/etc/rules/local.rules
fi

####### 6. PULLEDPORK3 #######
if ! component_installed "/usr/local/bin/pulledpork3/pulledpork.py"; then
    cd "$SRC_DIR"
    git clone https://github.com/shirkdog/pulledpork3.git
    sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
    sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
    sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
    sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
    
    # Create fresh config every time to ensure oinkcode is current
    sudo tee /usr/local/etc/pulledpork3/pulledpork.conf <<EOF
oinkcode=$OINKCODE
snort_path=/usr/local/bin/snort
local_rules=/usr/local/etc/rules/local.rules
rule_path=/usr/local/etc/rules/pulledpork.rules
rule_url=https://www.snort.org/rules/snortrules-snapshot-29120.tar.gz|$OINKCODE|snortrules-snapshot-29120.tar.gz
EOF
fi

# Only run if rules file is missing
if ! component_installed "/usr/local/etc/rules/pulledpork.rules"; then
    sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
fi

####### 7. FINAL SNORT CONFIG #######
if ! grep -q "alert_json" /etc/snort/snort.lua; then
    sudo tee -a /etc/snort/snort.lua <<EOF

alert_json = {
    file = true,
    limit = 100,
    filename = '/var/log/snort/alert_json.txt'
}
EOF
fi

echo "TIDSOC sensor setup complete. Components are installed and configured."