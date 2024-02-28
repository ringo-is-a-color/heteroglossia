# Notes

## Protocol Limitation

### SOCKS

It doesn't support SOCKS4 and UDP for SOCKS inbound.

### TLS carrier

* It doesn't support UDP for TLS carrier outbound.
* TLS carrier client isn't compatible with Trojan server.

## OS-Level

KDE: If you configure an IPv6 address with authentication info for HTTP inbound, the hg won't be able to configure this
as a system proxy due to a KDE bug.
