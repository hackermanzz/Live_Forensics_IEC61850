import importlib.util
import re
import yaml
from collections import defaultdict, Counter
from pathlib import Path

from packet_reader import iter_pcap

RB_ENGINE_DIR = Path(__file__).resolve().parent
PARSER_SPEC = importlib.util.spec_from_file_location("rb_engine_parser", RB_ENGINE_DIR / "parser.py")
if PARSER_SPEC is None or PARSER_SPEC.loader is None:
    raise ImportError(f"Unable to load parser module from {RB_ENGINE_DIR / 'parser.py'}")
RB_ENGINE_PARSER = importlib.util.module_from_spec(PARSER_SPEC)
PARSER_SPEC.loader.exec_module(RB_ENGINE_PARSER)
parse_packet = RB_ENGINE_PARSER.parse_packet


def extract_printable_strings(b, min_len=4):
    if not b:
        return []
    # find ASCII runs
    try:
        s = b.decode('latin1')
    except Exception:
        return []
    runs = re.findall(r'[ -~]{%d,}' % min_len, s)
    return runs


def infer_mappings(pcap_path, out_yaml='inferred_mappings.yml'):
    gocb_map = defaultdict(Counter)
    sv_map = defaultdict(Counter)

    for idx, ts, pkt in iter_pcap(pcap_path):
        feat = parse_packet(pkt, idx, ts)
        src = feat.get('src_mac')
        if feat.get('protocol') == 'GOOSE':
            raw = feat.get('goose_payload_raw')
            for tok in extract_printable_strings(raw):
                gocb_map[tok][src] += 1
        if feat.get('protocol') == 'SV':
            raw = feat.get('sv_payload_raw')
            for tok in extract_printable_strings(raw):
                sv_map[tok][src] += 1

    # build best-guess mappings
    gocb_to_mac = {}
    svid_to_mac = {}

    for tok, cnt in gocb_map.items():
        mac, c = cnt.most_common(1)[0]
        gocb_to_mac[tok] = mac

    for tok, cnt in sv_map.items():
        mac, c = cnt.most_common(1)[0]
        svid_to_mac[tok] = mac

    out = {
        'gocbref_to_mac': gocb_to_mac,
        'svid_to_mac': svid_to_mac,
    }

    with open(out_yaml, 'w') as f:
        yaml.safe_dump(out, f)

    print('Wrote inferred mappings to', out_yaml)
    print('Sample gocbRef mappings (count):')
    for k,v in list(gocb_map.items())[:10]:
        print(k, dict(v))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('pcap')
    p.add_argument('--out', default='inferred_mappings.yml')
    args = p.parse_args()
    infer_mappings(args.pcap, args.out)
