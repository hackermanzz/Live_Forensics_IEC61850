from scapy.all import PcapReader, Ether, Dot1Q

GOOSE_ETHERTYPE = 0x88B8
SV_ETHERTYPE = 0x88BA
VLAN_ETHERTYPE = 0x8100
IEC61850_ETHERTYPES = {GOOSE_ETHERTYPE, SV_ETHERTYPE}


def _inner_ethertype(pkt):
    if Ether not in pkt:
        return None

    eth_type = pkt[Ether].type
    if eth_type in IEC61850_ETHERTYPES:
        return eth_type

    if eth_type == VLAN_ETHERTYPE and Dot1Q in pkt:
        return pkt[Dot1Q].type

    return None


def is_goose_or_sv(pkt):
    """Fast EtherType check used before full packet parsing."""
    try:
        return _inner_ethertype(pkt) in IEC61850_ETHERTYPES
    except Exception:
        return False

def packet_protocol(pkt):
    """Return the IEC 61850 protocol from EtherType without full parsing."""
    try:
        eth_type = _inner_ethertype(pkt)
    except Exception:
        return None
    if eth_type == GOOSE_ETHERTYPE:
        return "GOOSE"
    if eth_type == SV_ETHERTYPE:
        return "SV"
    return None

def iter_pcap(path):
    """Yield (index, timestamp, ScapyPacket) from a pcap file."""
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            ts = getattr(pkt, "time", None)
            try:
                ts = float(ts)
            except Exception:
                pass
            yield i + 1, ts, pkt
