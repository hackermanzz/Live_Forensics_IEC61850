# IEC 61850 Rule-based Detector (Prototype)

This repository contains a minimal rule-based detection skeleton for IEC 61850 GOOSE and SV traffic.

Quick start (Google Colab / local):

1. Create and activate a local virtual environment, then install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the runner on a PCAP from the repository root (use relative paths):

```bash
python rulebasedengine.py my_capture.pcap --config config_example.yml --out alerts.jsonl
```

Notes:
- `parser.py` contains placeholder GOOSE/SV parsing functions. Replace with ASN.1/BER decoding suited to your captures.
- `mapping_infer.py` can scan a capture for human-readable GOOSE/SV identifiers such as `$simpleIOGenericIO/LLN0$AnalogValuesN` and `*simpleIOGenericIO/LLN0$GO$gcbAnalogValuesN`.
- `config_example.yml` should be filled with expected MAC mappings and identifier-to-bus mappings before live use.
- `.venv` is ignored by `.gitignore` and should not be committed to GitHub.
- The system currently flags rule violations and writes alerts to JSONL; no automatic blocking is performed.
