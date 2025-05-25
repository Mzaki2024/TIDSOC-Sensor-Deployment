#!/usr/bin/env bash
# install-snort3-ics.sh
# Installs Snort 3 with ICS protocol (BACnet/Modbus) rule validation

set -euo pipefail

# Configuration
INTERFACE="eth0"                # Update to your NIC
HOME_NET="10.0.1.0/24"          # Protected network
OINKCODE="d94e906f9d839665e4bb3f98f5cb3c783015b165"   # Get from snort.org
SRC_DIR="/usr/local/src"

# Install dependencies
sudo apt update && sudo apt install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool libpcre3-dev python3-pip

# Create working directory
sudo mkdir -p $SRC_DIR && cd $SRC_DIR

# Install SafeC
wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
tar -xzvf libsafec-02092020.tar.gz
cd libsafec-02092020.0-g6d921f
./configure && make && sudo make install
cd $SRC_DIR

# Install PCRE 8.45
wget -q https://downloads.sourceforge.net/project/pcre/pcre/8.45/pcre-8.45.tar.gz
tar -xzvf pcre-8.45.tar.gz
cd pcre-8.45 && ./configure && make && sudo make install
cd $SRC_DIR

# Install Hyperscan 5.4 dependencies
wget -q https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar -xzvf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1 && ./configure && make && sudo make install
cd $SRC_DIR

wget -q http://www.colm.net/files/ragel/ragel-6.10.tar.gz
tar -xzvf ragel-6.10.tar.gz
cd ragel-6.10 && ./configure && make && sudo make install
cd $SRC_DIR

# Install Boost 1.77
wget -q https://boostorg.jfrog.io/artifactory/main/release/1.77.0/source/boost_1_77_0.tar.gz
tar -xvzf boost_1_77_0.tar.gz

# Install Hyperscan
wget -q https://github.com/intel/hyperscan/archive/refs/tags/v5.4.0.tar.gz
tar -xvzf v5.4.0.tar.gz
mkdir hyperscan-5.4.0-build && cd hyperscan-5.4.0-build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBOOST_ROOT="$SRC_DIR/boost_1_77_0" ../hyperscan-5.4.0
make && sudo make install
cd $SRC_DIR

# Install FlatBuffers
wget -q https://github.com/google/flatbuffers/archive/refs/tags/v2.0.0.tar.gz -O flatbuffers-2.0.0.tar.gz
tar -xzvf flatbuffers-2.0.0.tar.gz
mkdir flatbuffers-build && cd flatbuffers-build
cmake ../flatbuffers-2.0.0 && make && sudo make install
cd $SRC_DIR

# Install libdaq
wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
tar -xzvf libdaq-3.0.5.tar.gz
cd libdaq-3.0.5 && ./bootstrap && ./configure && make && sudo make install
cd $SRC_DIR

sudo ldconfig

# Install Snort 3.1.17.0
wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
tar -xzvf snort3-3.1.17.0.tar.gz
cd snort3-3.1.17.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build && make && sudo make install

# Create user/group and directories
sudo useradd -r -s /usr/sbin/nologin -M snort || true
sudo mkdir -p /usr/local/etc/rules /usr/local/etc/so_rules /usr/local/etc/lists /var/log/snort
sudo chown -R snort:snort /var/log/snort
sudo chmod -R 5775 /var/log/snort

# ICS Protocol Rule Setup
echo 'alert udp any any -> any 47808 (msg:"BACnet protocol detected"; content:"|81 0a|"; depth:2; sid:1000001;)' | sudo tee /usr/local/etc/rules/ics.rules
echo 'alert tcp any any -> any 502 (msg:"Modbus protocol detected"; content:"|00 00|"; depth:2; sid:1000002;)' | sudo tee -a /usr/local/etc/rules/ics.rules

# Install PulledPork3
cd ~/snort_src
git clone https://github.com/shirkdog/pulledpork3.git
sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
sudo cp pulledpork3/etc/pulledpork.conf /usr/local/etc/pulledpork3/

# Configure PulledPork for ICS rules
sudo sed -i "s|rule_url=.*|rule_url=https://www.snort.org/rules/snortrules-snapshot-29120.tar.gz|$OINKCODE|snortrules-snapshot-29120.tar.gz|" /usr/local/etc/pulledpork3/pulledpork.conf
sudo sed -i "s|local_rules=.*|local_rules=/usr/local/etc/rules/ics.rules|" /usr/local/etc/pulledpork3/pulledpork.conf
sudo sed -i "s|sid_msg=.*|sid_msg=/usr/local/etc/sid-msg.map|" /usr/local/etc/pulledpork3/pulledpork.conf

# Run PulledPork and verify ICS rules
sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
if ! grep -q "BACnet\|Modbus" /usr/local/etc/rules/pulledpork.rules; then
  echo "No ICS rules found! Manual rule addition required."
  echo "Add custom rules to /usr/local/etc/rules/ics.rules"
fi

# Final Snort config
sudo tee /etc/snort/snort.lua <<EOF
HOME_NET = '$HOME_NET'
EXTERNAL_NET = 'any'
RULE_PATH = '/usr/local/etc/rules'
SO_RULE_PATH = '/usr/local/etc/so_rules'
LISTS_PATH = '/usr/local/etc/lists'

ips = {
    rules = [[ include $RULE_PATH/pulledpork.rules ]]
}

alert_json = {
    file = true,
    limit = 100,
    filename = '/var/log/snort/alert_json.txt'
}
EOF

echo "Snort 3 with ICS rule support installed successfully!"
