# Notes

## Protocol implementation limitation

### SOCKS inbound

It doesn't support SOCKS4 and UDP for SOCKS inbound.

### TLS carrier

It doesn't support UDP. Also, the TLS carrier client isn't compatible with the Trojan server, although the TLS carrier server is compatible with the Trojan client.

### Shadowsocks carrier

It doesn't support UDP, "2022-blake3-aes-256-gcm" method and "Shadowsocks 2022 Extensible Identity Headers" spec.

## Protocol design limitation

### Shadowsocks carrier

The time of the client's system cannot differ from the server's by more than half a minute.

## OS-Level

### KDE

If you configure an IPv6 address with authentication info for HTTP inbound, the hg won't be able to configure this as a system proxy due to a KDE bug.
