#!/usr/bin/env bash
set -euo pipefail

sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt-get update
sudo apt-get install -y suricata

sudo sed -i "s|HOME_NET: .*|HOME_NET: \"[10.0.1.0/24]\"|" /etc/suricata/suricata.yaml

sudo suricata-update

sudo systemctl enable --now suricata
