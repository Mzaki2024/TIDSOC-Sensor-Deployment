#!/usr/bin/env bash
set -euo pipefail

INTERFACE="ens33"

cat <<EOF | sudo tee /etc/systemd/system/disable-offload.service
[Unit]
Description=Disable NIC Offloading (GRO/LRO)
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
