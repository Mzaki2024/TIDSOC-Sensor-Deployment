#!/usr/bin/env bash
set -euo pipefail

cd ~/snort_src
git clone https://github.com/shirkdog/pulledpork3.git
sudo mkdir -p /usr/local/bin/pulledpork3 /usr/local/etc/pulledpork3
sudo cp pulledpork3/pulledpork.py /usr/local/bin/pulledpork3/
sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
sudo cp -r pulledpork3/lib /usr/local/bin/pulledpork3/
sudo cp pulledpork3/etc/pulledpork.conf /usr/local/etc/pulledpork3/
echo "Edit /usr/local/etc/pulledpork3/pulledpork.conf to set oinkcode and rule paths."
