#!/usr/bin/env bash
set -euo pipefail

# Download Splunk Enterprise (trial)
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6b9c8185839-Linux-x86_64.tgz'
sudo tar -xzvf splunk.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1
