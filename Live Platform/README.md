# IEC 61850 Live Forensic Platform

This project runs a local web platform for monitoring IEC 61850 GOOSE and SV traffic. It supports two modes:

- PCAP Replay: upload a `.pcap` or `.pcapng` file and replay it through the rule-based engine, then the GOOSE/SV ML ensembles.
- Live Capture: select a network interface and monitor live GOOSE/SV packets from the operational network.

The current pipeline is:

1. Capture or replay packet.
2. Ignore non-GOOSE/SV traffic.
3. Run rule-based detection first.
4. If no rule violation is found, run the protocol-specific ML ensemble.
5. Group alerts and show statistics in the frontend.

## Folder Contents

- `live_platform/` - FastAPI backend, replay/live capture logic, alert storage, ML adapter.
- `templates/` - Web frontend pages.
- `rb engine/` - Rule-based parser and rule engine.
- `models/` - Current joblib ML models.
- `pcaps/` - Test PCAP files.
- `tests/` - Regression tests.
- `requirements_live.txt` - Python dependencies for the live platform.

## Before Going Onsite

Make sure these files are present:

```text
models/rf_goose_detector.joblib
models/xgb_goose_detector.joblib
models/rf_sv_detector.joblib
models/xgb_sv_detector.joblib
live_platform/config_example.yml
requirements_live.txt
```

Also check `live_platform/config_example.yml` before testing onsite. This file contains the expected GOOSE/SV mappings used by the rule engine.

## Onsite PC Setup

Use Windows PowerShell from the project folder.

```powershell
cd C:\path\to\ITP_ML
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements_live.txt
```

On Windows, live packet capture normally requires Npcap. Install Npcap on the onsite PC if Scapy cannot capture packets. During installation, enable WinPcap-compatible mode if available.

## Run The Platform

From inside `ITP_ML`:

```powershell
.\.venv\Scripts\python.exe -m uvicorn live_platform.app:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

Pages:

- `http://127.0.0.1:8000/replay` - PCAP replay testing.
- `http://127.0.0.1:8000/live` - Live network capture.
- `http://127.0.0.1:8000/monitor` - IED monitor page.

## Quick Health Check

In a second PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
Invoke-RestMethod http://127.0.0.1:8000/api/engine-status
```

The engine status should show:

- Rule engine enabled.
- GOOSE model ensemble loaded.
- SV model ensemble loaded.

## PCAP Replay Test

1. Open `/replay`.
2. Upload a PCAP from `pcaps/`.
3. Click `Replay PCAP`.
4. Watch Live Alerts, risk score, packet counts, and replay status.
5. Use `Stop Replay` or `Clear` if a replay is taking too long.

Notes:

- The replay path only processes GOOSE/SV packets.
- Non-GOOSE/SV packets are counted as skipped traffic.
- Refreshing the browser should not stop the backend replay. The page should reconnect to the active replay job.

## Live Capture Onsite Test

1. Connect the onsite PC to the correct network source, such as a mirrored switch port, TAP, or VM network interface carrying IEC 61850 traffic.
2. Open `/live`.
3. Click `Refresh Interfaces`.
4. Select the interface connected to the mirrored/TAP/IEC network.
5. Click `Diagnostic 5s`.
6. Confirm the diagnostic packet count increases.
7. Click `Start Live`.
8. Confirm processed GOOSE/SV packet counts increase.
9. Check Live Alerts and IED Monitor.

Important:

- `Diagnostic 5s` captures any packet type. It proves the adapter can capture traffic.
- `Start Live` captures only GOOSE/SV using this filter:

```text
ether proto 0x88b8 or ether proto 0x88ba
```

If diagnostic packets increase but live GOOSE/SV stays at zero, the capture stack works, but the selected interface may not be receiving IEC 61850 GOOSE/SV traffic.

## Live Capture Checklist

If live capture shows zero packets onsite, check:

- Correct network interface selected.
- PowerShell or terminal is running with enough permissions.
- Npcap is installed.
- The switch mirror/TAP is configured correctly.
- The selected interface can see Layer 2 Ethernet traffic.
- The network actually contains GOOSE EtherType `0x88b8` or SV EtherType `0x88ba`.
- Firewall/security tools are not blocking packet capture.

## Clearing State

Use the `Clear` button in the frontend to clear:

- Alerts.
- Incidents.
- Recent packet memory.
- Replay history.
- IED monitor state.

`Clear` also stops any currently running PCAP replay.

Stored runtime state lives in:

```text
live_platform/data/live_state.json
```

## Running Tests

From inside `ITP_ML`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_live_platform.py
```

## Model Files

The platform loads these default model files:

```text
models/rf_goose_detector.joblib
models/xgb_goose_detector.joblib
models/rf_sv_detector.joblib
models/xgb_sv_detector.joblib
```

Optional environment variables can override them:

```powershell
$env:GOOSE_RF_MODEL="C:\path\to\rf_goose_detector.joblib"
$env:GOOSE_XGB_MODEL="C:\path\to\xgb_goose_detector.joblib"
$env:SV_RF_MODEL="C:\path\to\rf_sv_detector.joblib"
$env:SV_XGB_MODEL="C:\path\to\xgb_sv_detector.joblib"
```

Set these before starting Uvicorn.

## Troubleshooting

Port already in use:

```powershell
netstat -ano | Select-String ":8000"
```

Then stop the listed process ID:

```powershell
Stop-Process -Id <PID> -Force
```

Interface list is empty:

- Check Npcap installation.
- Try running PowerShell as Administrator.
- Use the manual interface name field if needed.

Live page refreshes:

- Refreshing the browser does not stop live capture or replay.
- Restarting the backend server does stop live capture and any active replay job.

Too many alerts:

- Alerts are grouped by incident category and source context.
- Click an alert row to inspect rule causes and packet evidence.
- Use `Clear` before starting a new test run.
