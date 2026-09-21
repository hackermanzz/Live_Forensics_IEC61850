"""Rule-based detection runner for IEC 61850 GOOSE/SV packets.

This runner reads a PCAP, parses packets, applies rule-based checks,
and writes alerts to a CSV/JSONL log. Payload parsing for GOOSE/SV is
left as placeholders; replace with ASN.1/BER decoding specific to your PCAPs.
"""

import argparse
import csv
import importlib.util
import json
from pathlib import Path

from packet_reader import iter_pcap
from state_manager import StateManager
from rule_engine import check_rules

RB_ENGINE_DIR = Path(__file__).resolve().parent
PARSER_SPEC = importlib.util.spec_from_file_location("rb_engine_parser", RB_ENGINE_DIR / "parser.py")
if PARSER_SPEC is None or PARSER_SPEC.loader is None:
    raise ImportError(f"Unable to load parser module from {RB_ENGINE_DIR / 'parser.py'}")
RB_ENGINE_PARSER = importlib.util.module_from_spec(PARSER_SPEC)
PARSER_SPEC.loader.exec_module(RB_ENGINE_PARSER)
parse_packet = RB_ENGINE_PARSER.parse_packet


def load_config(path):
	import yaml

	with open(path, "r") as f:
		return yaml.safe_load(f)


def run(pcap_path, config_path, out_path):
	cfg = load_config(config_path)
	state = StateManager(cfg)

	out_path = Path(out_path)
	out_path.parent.mkdir(parents=True, exist_ok=True)

	alerts = []
	for idx, ts, scapy_pkt in iter_pcap(pcap_path):
		feat = parse_packet(scapy_pkt, idx, ts)
		res = check_rules(feat, state)

		excluded_buses = set(cfg.get("excluded_buses", []))
		if feat.get("bus_num") not in excluded_buses:
			# update state only for non-excluded buses
			if feat.get("protocol") == "GOOSE":
				state.update_goose(feat.get("gocbRef"), feat.get("stNum"), feat.get("sqNum"), feat.get("timestamp"), feat.get("src_mac"))
			elif feat.get("protocol") == "SV":
				state.update_sv(feat.get("svID"), feat.get("smpCnt"), feat.get("timestamp"), feat.get("src_mac"))

		if res.get("rule_violation"):
			alert = {
				"time": feat.get("timestamp"),
				"index": feat.get("index"),
				"protocol": feat.get("protocol"),
				"bus_num": feat.get("bus_num"),
				"src_mac": feat.get("src_mac"),
				"dst_mac": feat.get("dst_mac"),
				"gocbRef": feat.get("gocbRef"),
				"svID": feat.get("svID"),
				"stNum": feat.get("stNum"),
				"sqNum": feat.get("sqNum"),
				"smpCnt": feat.get("smpCnt"),
				"reasons": res.get("reasons"),
				"severity": res.get("severity"),
			}
			alerts.append(alert)

	# write JSONL alerts
	with open(out_path, "w") as f:
		for a in alerts:
			f.write(json.dumps(a) + "\n")

	print(f"Wrote {len(alerts)} alerts to {out_path}")


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("pcap", help="PCAP file to analyze")
	parser.add_argument("--config", default="config_example.yml", help="Path to config YAML")
	parser.add_argument("--out", default="alerts.jsonl", help="Output alerts file")
	args = parser.parse_args()
	run(args.pcap, args.config, args.out)


if __name__ == "__main__":
	main()

