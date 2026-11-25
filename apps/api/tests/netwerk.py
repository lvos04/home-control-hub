"""Onafhankelijke testnetwerken. Kies hosts met een index binnen het bereik dat de proef nodig heeft."""

from ipaddress import IPv4Network, IPv6Network

# Privénetten voor de LAN- en VPN-proeven (RFC 1918).
LAN = IPv4Network((bytes((192, 168, 10, 0)), 24))
VPN = IPv4Network((bytes((10, 8, 0, 0)), 24))
PRIVE_10 = VPN.supernet(new_prefix=8)
PRIVE_172 = IPv4Network((bytes((172, 16, 5, 0)), 24))

ULA = IPv6Network((0xFD << 120, 48))
CGNAT = IPv4Network((bytes((100, 64, 0, 0)), 10))
CGNAT_CLIENT = CGNAT[CGNAT.num_addresses // 2 + 5]
LINK_LOCAL = IPv4Network((bytes((169, 254, 0, 0)), 16))
ALLE_ADRESSEN = IPv4Network((0, 0))
PUBLIEK = IPv4Network((8 << 24, 24))  # wereldwijd routeerbaar, alleen invoer voor bereikvalidatie

# Documentatienetten (RFC 5737) voor fictieve clients en voor de verwachte externe proefhost.
TEST_NET_1 = IPv4Network((bytes((192, 0, 2, 0)), 24))
TEST_NET_3 = IPv4Network((bytes((203, 0, 113, 0)), 24))
