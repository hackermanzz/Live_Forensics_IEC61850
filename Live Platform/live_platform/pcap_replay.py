import json
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]

from live_platform.pipeline import DetectionPipeline, load_config
from live_platform.storage import LiveStore


class PcapReplay:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self.config = load_config(config_path)
        self.store = LiveStore(ROOT_DIR / "live_platform" / "data" / "replay_state.json")
        self.pipeline = DetectionPipeline(config_path, self.store)

    def _load_config(self, path: str) -> Dict[str, Any]:
        return load_config(path)

    def replay_file(self, pcap_path: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        result = self.replay_file_with_summary(pcap_path, limit=limit)
        if result["alerts"]:
            return result["alerts"]
        return [{
                "source": "replay",
                "protocol": "PCAP",
                "severity": "info",
                "message": "No suspicious detections found in this replay",
                "details": {
                    "pcap_path": pcap_path,
                    "packets_processed": result["summary"]["packets_processed"],
                    "risk_score": result["summary"]["risk_score"],
                },
            }]

    def replay_file_with_summary(self, pcap_path: str, limit: Optional[int] = None) -> Dict[str, Any]:
        return self.pipeline.replay_file(pcap_path, limit=limit)


def post_alerts_to_backend(alerts: List[Dict[str, Any]], base_url: str = "http://127.0.0.1:8000/api/ingest-detection") -> List[Dict[str, Any]]:
    posted = []
    for alert in alerts:
        req = urllib.request.Request(
            base_url,
            data=json.dumps(alert).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                posted.append(json.loads(response.read().decode("utf-8")))
        except Exception as exc:
            posted.append({"error": str(exc), **alert})
    return posted
