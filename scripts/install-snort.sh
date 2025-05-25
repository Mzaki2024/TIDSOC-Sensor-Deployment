#!/usr/bin/env bash
set -euo pipefail

# Variables
INTERFACE="ens33"
HOME_NET="10.0.1.0/24"

sudo apt-get update && sudo apt-get install -y \
  build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev \
  libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev \
  openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git \
  autoconf bison flex libcmocka-dev libnetfilter-queue-dev \
  libunwind-dev libmnl-dev ethtool libpcre3-dev

mkdir -p "$HOME/snort_src" && cd "$HOME/snort_src"

# SafeC
wget -q https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-02092020.tar.gz
tar -xzvf libsafec-02092020.tar.gz
cd libsafec-02092020.0-g6d921f
./configure && make && sudo make install
cd "$HOME/snort_src"

# PCRE
wget -q https://downloads.sourceforge.net/project/pcre/pcre/8.45/pcre-8.45.tar.gz
tar -xzvf pcre-8.45.tar.gz
cd pcre-8.45
./configure && make && sudo make install
cd "$HOME/snort_src"

# gperftools
wget -q https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
tar -xzvf gperftools-2.9.1.tar.gz
cd gperftools-2.9.1
./configure && make && sudo make install
cd "$HOME/snort_src"

# Ragel
wget -q http://www.colm.net/files/ragel/ragel-6.10.tar.gz
tar -xzvf ragel-6.10.tar.gz
cd ragel-6.10
./configure && make && sudo make install
cd "$HOME/snort_src"

# Boost
wget -q https://boostorg.jfrog.io/artifactory/main/release/1.77.0/source/boost_1_77_0.tar.gz
tar -xzvf boost_1_77_0.tar.gz

# Hyperscan
wget -q https://github.com/intel/hyperscan/archive/refs/tags/v5.4.0.tar.gz
tar -xzvf v5.4.0.tar.gz
mkdir hyperscan-5.4.0-build && cd hyperscan-5.4.0-build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBOOST_ROOT="$HOME/snort_src/boost_1_77_0" ../hyperscan-5.4.0
make && sudo make install
cd "$HOME/snort_src"

# FlatBuffers
wget -q https://github.com/google/flatbuffers/archive/refs/tags/v2.0.0.tar.gz -O flatbuffers-2.0.0.tar.gz
tar -xzvf flatbuffers-2.0.0.tar.gz
mkdir flatbuffers-build && cd flatbuffers-build
cmake ../flatbuffers-2.0.0 && make && sudo make install
cd "$HOME/snort_src"

# libdaq
wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.5.tar.gz -O libdaq-3.0.5.tar.gz
tar -xzvf libdaq-3.0.5.tar.gz
cd libdaq-3.0.5
./bootstrap && ./configure && make && sudo make install
cd "$HOME/snort_src"

sudo ldconfig

# Snort 3
wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.17.0.tar.gz -O snort3-3.1.17.0.tar.gz
tar -xzvf snort3-3.1.17.0.tar.gz
cd snort3-3.1.17.0
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make && sudo make install

echo "Snort 3 installation complete."
