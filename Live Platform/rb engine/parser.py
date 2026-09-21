from scapy.all import Ether, Dot1Q
import re
import struct

try:
    from scapy.layers.inet import IP
except Exception:
    IP = None
try:
    from scapy.layers.inet6 import IPv6
except Exception:
    IPv6 = None

GOOSE_ETHERTYPE = 0x88b8
SV_ETHERTYPE = 0x88ba
VLAN_ETHERTYPE = 0x8100

GOOSE_ID_PATTERN = re.compile(rb'\*?simpleIOGenericIO/LLN0\$GO\$gcbAnalogValues[0-9]+')
SV_ID_PATTERN = re.compile(rb'\*?\$simpleIOGenericIO/LLN0\$AnalogValues[0-9]+')
SVPUB_ID_PATTERN = re.compile(rb'svpub_values_bus[0-9]+')


def parse_packet(pkt, index, ts):
    """Return a feature dict with common fields and protocol-specific placeholders."""
    out = {
        "index": index,
        "timestamp": ts,
        "protocol": None,
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "eth_type": None,
        "pkt_len": None,
    }

    if not pkt or not hasattr(pkt, "payload"):
        return out

    if Ether in pkt:
        eth = pkt[Ether]
        out["src_mac"] = eth.src
        out["dst_mac"] = eth.dst
        out["pkt_len"] = len(pkt)

        eth_type = eth.type
        payload = bytes(pkt.payload)

        if eth_type == VLAN_ETHERTYPE and Dot1Q in pkt:
            vlan = pkt[Dot1Q]
            eth_type = vlan.type
            payload = bytes(vlan.payload)

        out["eth_type"] = eth_type

        # extract IP addresses when available
        try:
            if IP and pkt.haslayer(IP):
                ip = pkt[IP]
                out["src_ip"] = ip.src
                out["dst_ip"] = ip.dst
            elif IPv6 and pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                out["src_ip"] = ip6.src
                out["dst_ip"] = ip6.dst
        except Exception:
            pass

        if eth_type == GOOSE_ETHERTYPE:
            out["protocol"] = "GOOSE"
            out.update(parse_goose(payload))
        elif eth_type == SV_ETHERTYPE:
            sv_features = parse_sv(payload)
            out["protocol"] = "SV"
            if isinstance(sv_features, list) and sv_features:
                out.update(sv_features[0])
                out["sv_asdus"] = sv_features
            else:
                out.update(sv_features)
        else:
            out["protocol"] = "OTHER"

    return out


def _ber_parse(data, offset=0):
    results = []
    while offset + 2 <= len(data):
        tag = data[offset]
        length_byte = data[offset + 1]
        offset2 = offset + 2
        if length_byte & 0x80:
            length_len = length_byte & 0x7F
            if offset2 + length_len > len(data):
                break
            length = int.from_bytes(data[offset2:offset2 + length_len], "big")
            offset2 += length_len
        else:
            length = length_byte
        if offset2 + length > len(data):
            break
        value = data[offset2:offset2 + length]
        results.append((tag, value))
        if tag & 0x20:
            results.extend(_ber_parse(value, 0))
        offset = offset2 + length
    return results


def _find_first_ber(data):
    for i in range(min(32, len(data))):
        if data[i] == 0x61:
            return i
    return 0


def _find_first_tag(data, wanted):
    for i in range(min(32, len(data))):
        if data[i] == wanted:
            return i
    return 0


def _extract_ascii(data, pattern):
    m = pattern.search(data)
    if not m:
        return None
    try:
        return m.group(0).decode("ascii")
    except Exception:
        return None


def _int_from_bytes(raw_bytes):
    if not raw_bytes:
        return None
    return int.from_bytes(raw_bytes, "big")


def parse_goose(raw_bytes):
    out = {
        "gocbRef": None,
        "stNum": None,
        "sqNum": None,
        "datSet": None,
        "goID": None,
        "goose_ttl": None,
        "goose_timestamp": None,
        "confRev": None,
        "ndsCom": None,
        "numDatSetEntries": None,
        "goose_data_raw": None,
        "breaker_signal": None,
        "breaker_status": None,
        "goose_payload_raw": raw_bytes,
        "bus_num": None,
    }

    start = _find_first_ber(raw_bytes)
    ber_bytes = raw_bytes[start:]
    items = _ber_parse(ber_bytes)

    for tag, value in items:
        if tag == 0x80:
            out["gocbRef"] = value.decode("ascii", errors="ignore")
        elif tag == 0x81:
            out["goose_ttl"] = _int_from_bytes(value)
        elif tag == 0x82:
            out["datSet"] = value.decode("ascii", errors="ignore")
        elif tag == 0x83:
            out["goID"] = value.decode("ascii", errors="ignore")
        elif tag == 0x84:
            out["goose_timestamp"] = value.hex()
        elif tag == 0x85:
            out["stNum"] = _int_from_bytes(value)
        elif tag == 0x86:
            out["sqNum"] = _int_from_bytes(value)
        elif tag == 0x87:
            out["test"] = _int_from_bytes(value)
        elif tag == 0x88:
            out["confRev"] = _int_from_bytes(value)
        elif tag == 0x89:
            out["ndsCom"] = _int_from_bytes(value)
        elif tag == 0x8A:
            out["numDatSetEntries"] = _int_from_bytes(value)
        elif tag == 0xAB:
            out["goose_data_raw"] = value

    if out["goose_data_raw"] is not None:
        values = _ber_parse(out["goose_data_raw"])
        for tag, value in values:
            if tag == 0x83 and value:
                out["breaker_signal"] = value != b"\x00"
                out["breaker_status"] = "trip/open signal active" if out["breaker_signal"] else "normal/closed signal"
                break

    if not out["gocbRef"]:
        out["gocbRef"] = _extract_ascii(raw_bytes, GOOSE_ID_PATTERN)
    if not out["datSet"]:
        out["datSet"] = _extract_ascii(raw_bytes, SV_ID_PATTERN)

    return out


def _read_length(data, offset):
    if offset >= len(data):
        return None, offset
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        return first, offset
    length_len = first & 0x7F
    if offset + length_len > len(data):
        return None, offset
    value = int.from_bytes(data[offset:offset + length_len], "big")
    return value, offset + length_len


def _decode_sv_payload(raw_bytes):
    result = {
        "noASDU": None,
        "svID": None,
        "smpCnt": None,
        "confRev": None,
        "smpSynch": None,
        "seqData": None,
        "simulated": None,
        "asdus": [],
    }

    if len(raw_bytes) < 8:
        return result

    result["simulated"] = bool(raw_bytes[4] & 0x80)
    offset = 8

    if offset >= len(raw_bytes) or raw_bytes[offset] != 0x60:
        return result
    offset += 1

    outer_len, offset = _read_length(raw_bytes, offset)
    if outer_len is None:
        return result
    end = offset + outer_len
    if end > len(raw_bytes):
        end = len(raw_bytes)

    tag = raw_bytes[offset] if offset < len(raw_bytes) else None
    if tag == 0x80:
        offset += 1
        length, offset = _read_length(raw_bytes, offset)
        if length is not None and offset + length <= len(raw_bytes):
            result["noASDU"] = int.from_bytes(raw_bytes[offset:offset + length], "big")
            offset += length

    if offset >= len(raw_bytes):
        return result

    tag = raw_bytes[offset]
    offset += 1
    seq_len, offset = _read_length(raw_bytes, offset)
    if seq_len is None:
        return result
    seq_end = offset + seq_len
    if seq_end > len(raw_bytes):
        seq_end = len(raw_bytes)

    if tag != 0xA2:
        return result

    while offset < seq_end:
        if offset >= len(raw_bytes):
            break
        asdu_tag = raw_bytes[offset]
        offset += 1
        asdu_len, offset = _read_length(raw_bytes, offset)
        if asdu_len is None:
            break
        asdu_end = offset + asdu_len
        if asdu_end > len(raw_bytes):
            asdu_end = len(raw_bytes)

        asdu = {
            "svID": None,
            "smpCnt": None,
            "confRev": None,
            "smpSynch": None,
            "seqData": None,
        }

        while offset < asdu_end and offset < len(raw_bytes):
            field_tag = raw_bytes[offset]
            offset += 1
            field_len, offset = _read_length(raw_bytes, offset)
            if field_len is None:
                break
            if offset + field_len > len(raw_bytes):
                break
            value = raw_bytes[offset:offset + field_len]
            offset += field_len

            if field_tag == 0x80:
                asdu["svID"] = value.decode("ascii", errors="replace").rstrip("\x00")
            elif field_tag == 0x82:
                asdu["smpCnt"] = _int_from_bytes(value)
            elif field_tag == 0x83:
                asdu["confRev"] = _int_from_bytes(value)
            elif field_tag == 0x85:
                asdu["smpSynch"] = _int_from_bytes(value)
            elif field_tag == 0x87:
                asdu["seqData"] = value.hex()

        if asdu["svID"] or asdu["smpCnt"] is not None or asdu["confRev"] is not None:
            result["asdus"].append(asdu)

        offset = asdu_end

    return result


def parse_sv(raw_bytes):
    decoded = _decode_sv_payload(raw_bytes)
    if not decoded.get("asdus"):
        out = {
            "svID": None,
            "smpCnt": None,
            "confRev": None,
            "phaseA_voltage": None,
            "phaseB_voltage": None,
            "phaseC_voltage": None,
            "phaseA_current": None,
            "phaseB_current": None,
            "phaseC_current": None,
            "sv_payload_raw": raw_bytes,
            "bus_num": None,
            "noASDU": decoded.get("noASDU"),
            "smpSynch": decoded.get("smpSynch"),
            "simulated": decoded.get("simulated"),
        }
        out["svID"] = _extract_ascii(raw_bytes, SV_ID_PATTERN)
        if out["svID"] is None:
            out["svID"] = _extract_ascii(raw_bytes, SVPUB_ID_PATTERN)
        if out["svID"] is None:
            out["svID"] = _extract_ascii(raw_bytes, GOOSE_ID_PATTERN)
        return [out]

    features = []
    for asdu in decoded["asdus"]:
        feature = {
            "svID": asdu.get("svID"),
            "smpCnt": asdu.get("smpCnt"),
            "confRev": asdu.get("confRev"),
            "phaseA_voltage": None,
            "phaseB_voltage": None,
            "phaseC_voltage": None,
            "phaseA_current": None,
            "phaseB_current": None,
            "phaseC_current": None,
            "sv_payload_raw": raw_bytes,
            "bus_num": None,
            "noASDU": decoded.get("noASDU"),
            "smpSynch": asdu.get("smpSynch"),
            "simulated": decoded.get("simulated"),
        }
        seq_data = asdu.get("seqData")
        if seq_data:
            values = _parse_seq_data(bytes.fromhex(seq_data))
            if len(values) >= 6:
                feature["phaseA_voltage"] = values[0]
                feature["phaseB_voltage"] = values[1]
                feature["phaseC_voltage"] = values[2]
                feature["phaseA_current"] = values[3]
                feature["phaseB_current"] = values[4]
                feature["phaseC_current"] = values[5]
        features.append(feature)

    return features


def _parse_seq_data(value):
    values = []
    for i in range(0, len(value), 4):
        chunk = value[i:i + 4]
        if len(chunk) != 4:
            continue
        try:
            values.append(struct.unpack("!f", chunk)[0])
        except Exception:
            values.append(_int_from_bytes(chunk))
    return values
