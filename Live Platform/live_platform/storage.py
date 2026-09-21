from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_STATE: Dict[str, Any] = {
    "alerts": [],
    "alert_groups": {},
    "incidents": [],
    "stats": {
        "total_packets": 0,
        "total_detections": 0,
        "protocol_counts": {"GOOSE": 0, "SV": 0, "OTHER": 0, "UNKNOWN": 0},
        "source_counts": {},
        "bus_counts": {},
        "rule_evaluated": 0,
        "ml_evaluated": 0,
        "replays": [],
        "last_packet_at": None,
        "capture_start_ts": None,
        "capture_end_ts": None,
        "capture_duration_seconds": None,
        "performance": {},
    },
    "packets": [],
    "ied_status": {},
}


class LiveStore:
    def __init__(self, path: Any, packet_limit: int = 500) -> None:
        self.path = Path(path)
        self.packet_limit = packet_limit
        self.state = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return deepcopy(DEFAULT_STATE)
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except Exception:
            return deepcopy(DEFAULT_STATE)

        state = deepcopy(DEFAULT_STATE)
        for key, value in loaded.items():
            if isinstance(value, dict) and isinstance(state.get(key), dict):
                state[key].update(value)
            else:
                state[key] = value
        return state

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(self.state, handle, indent=2)
        temp_path.replace(self.path)

    def clear(self) -> Dict[str, Any]:
        self.state = deepcopy(DEFAULT_STATE)
        self.save()
        return self.snapshot()

    def snapshot(self) -> Dict[str, Any]:
        return deepcopy(self.state)

    def alerts(self) -> List[Dict[str, Any]]:
        return self.state["alerts"]

    def incidents(self) -> List[Dict[str, Any]]:
        return self.state["incidents"]

    def add_packet(self, feature: Dict[str, Any]) -> None:
        self.add_packets([feature])

    def add_packets(self, features: List[Dict[str, Any]], update_ied: bool = False) -> None:
        if not features:
            return
        stats = self.state["stats"]
        now = datetime.now(timezone.utc).isoformat()
        protocol_counts = stats["protocol_counts"]
        source_counts = stats["source_counts"]
        bus_counts = stats["bus_counts"]

        for feature in features:
            protocol = feature.get("protocol") or "UNKNOWN"
            src_mac = feature.get("src_mac") or "unknown"
            bus_num = feature.get("bus_num") or "unknown"

            stats["total_packets"] += 1
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            source_counts[src_mac] = source_counts.get(src_mac, 0) + 1
            bus_counts[bus_num] = bus_counts.get(bus_num, 0) + 1
            self._update_capture_span(feature.get("timestamp"))
            if update_ied:
                self.add_ied_observation(feature)

        stats["last_packet_at"] = now
        self.state["packets"][:0] = reversed(features)
        del self.state["packets"][self.packet_limit:]

    def add_ied_observation(self, feature: Dict[str, Any]) -> None:
        bus_num = feature.get("bus_num")
        if not bus_num:
            return
        devices = self.state.setdefault("ied_status", {})
        current = devices.setdefault(bus_num, {"bus": bus_num})
        current["bus"] = bus_num
        current["last_seen"] = feature.get("received_at")
        current["last_capture_ts"] = feature.get("timestamp")
        current["last_protocol"] = feature.get("protocol")
        current["packet_index"] = feature.get("index")
        current["packet_count"] = current.get("packet_count", 0) + 1

        if feature.get("protocol") == "GOOSE":
            current["goose_src_mac"] = feature.get("src_mac")
            current["src_mac"] = feature.get("src_mac")
            current["gocbRef"] = feature.get("gocbRef")
            current["stNum"] = feature.get("stNum")
            current["sqNum"] = feature.get("sqNum")
            current["breaker_signal"] = feature.get("breaker_signal")
            current["breaker_status"] = feature.get("breaker_status") or current.get("breaker_status")
        elif feature.get("protocol") == "SV":
            current["sv_src_mac"] = feature.get("src_mac")
            current["src_mac"] = feature.get("src_mac")
            current["svID"] = feature.get("svID")
            current["smpCnt"] = feature.get("smpCnt")
            current["confRev"] = feature.get("confRev")
            voltage = {
                "phaseA": feature.get("phaseA_voltage"),
                "phaseB": feature.get("phaseB_voltage"),
                "phaseC": feature.get("phaseC_voltage"),
            }
            amperage = {
                "phaseA": feature.get("phaseA_current"),
                "phaseB": feature.get("phaseB_current"),
                "phaseC": feature.get("phaseC_current"),
            }
            if any(value is not None for value in voltage.values()):
                current["voltage"] = voltage
            if any(value is not None for value in amperage.values()):
                current["current"] = amperage

    def add_replay(self, summary: Dict[str, Any]) -> None:
        self.state["stats"]["replays"].insert(0, summary)
        del self.state["stats"]["replays"][20:]

    def record_timing(self, name: str, elapsed_seconds: float, count: int = 1) -> None:
        performance = self.state["stats"].setdefault("performance", {})
        metric = performance.setdefault(name, {
            "count": 0,
            "total_seconds": 0.0,
            "max_seconds": 0.0,
        })
        metric["count"] += count
        metric["total_seconds"] += elapsed_seconds
        metric["max_seconds"] = max(metric.get("max_seconds", 0.0), elapsed_seconds)
        metric["avg_seconds"] = metric["total_seconds"] / max(metric["count"], 1)

    def ied_status(self) -> Dict[str, Any]:
        return deepcopy(self.state.get("ied_status", {}))

    def add_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert = dict(alert)
        self.state["stats"]["total_detections"] = self.state["stats"].get("total_detections", 0) + 1
        alert.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        alert.setdefault("severity", "low")
        alert.setdefault("source", "unknown")
        alert.setdefault("protocol", "UNKNOWN")
        alert.setdefault("message", "")
        alert.setdefault("details", {})
        group_key = alert.get("group_key") or self._fallback_group_key(alert)
        alert["group_key"] = group_key

        existing_id = self.state.setdefault("alert_groups", {}).get(group_key)
        if existing_id is not None:
            existing = self._find_alert(existing_id)
            if existing is not None:
                self._update_grouped_alert(existing, alert)
                self._move_alert_to_front(existing["id"])
                self._update_incident(existing)
                return deepcopy(existing)

        alert["id"] = len(self.state["alerts"]) + 1
        alert["first_seen"] = alert["timestamp"]
        alert["last_seen"] = alert["timestamp"]
        alert["occurrence_count"] = 1
        alert["details"] = self._prepare_group_details(alert.get("details") or {})
        self.state["alerts"].insert(0, alert)
        self.state["alert_groups"][group_key] = alert["id"]
        if alert["severity"] in {"critical", "high", "medium"}:
            self.state["incidents"].insert(0, {
                "id": len(self.state["incidents"]) + 1,
                "timestamp": alert["timestamp"],
                "message": f"{alert['protocol']} alert from {alert['source']}: {alert['message']}",
                "severity": alert["severity"],
                "alert_id": alert["id"],
                "occurrence_count": alert["occurrence_count"],
            })
        return deepcopy(alert)

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        for alert in self.state["alerts"]:
            if alert.get("id") == alert_id:
                return deepcopy(alert)
        return None

    def _find_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        for alert in self.state["alerts"]:
            if alert.get("id") == alert_id:
                return alert
        return None

    def _move_alert_to_front(self, alert_id: int) -> None:
        for index, alert in enumerate(self.state["alerts"]):
            if alert.get("id") == alert_id:
                self.state["alerts"].insert(0, self.state["alerts"].pop(index))
                return

    def _update_grouped_alert(self, existing: Dict[str, Any], incoming: Dict[str, Any]) -> None:
        existing["last_seen"] = incoming["timestamp"]
        existing["timestamp"] = incoming["timestamp"]
        existing["occurrence_count"] = existing.get("occurrence_count", 1) + 1
        existing["severity"] = self._max_severity(existing.get("severity", "low"), incoming.get("severity", "low"))

        details = existing.setdefault("details", {})
        incoming_details = incoming.get("details") or {}
        existing["message"] = incoming.get("message") or existing.get("message")
        details["latest_packet"] = incoming_details.get("packet")
        details["latest_detection"] = incoming_details
        self._merge_detail_list(details, incoming_details, "rules_violated")
        self._merge_detail_list(details, incoming_details, "rule_labels")
        existing["message"] = self._merged_rule_message(existing)
        details.setdefault("evidence_packets", [])
        packet = incoming_details.get("packet")
        if packet and len(details["evidence_packets"]) < 10:
            details["evidence_packets"].append(packet)
        packet_index = packet.get("index") if isinstance(packet, dict) else None
        if packet_index is not None:
            details.setdefault("packet_indexes_sample", [])
            if len(details["packet_indexes_sample"]) < 25:
                details["packet_indexes_sample"].append(packet_index)

    def _merge_detail_list(self, details: Dict[str, Any], incoming_details: Dict[str, Any], key: str) -> None:
        values = []
        for item in details.get(key) or []:
            if item not in values:
                values.append(item)
        for item in incoming_details.get(key) or []:
            if item not in values:
                values.append(item)
        if values:
            details[key] = values

    def _merged_rule_message(self, alert: Dict[str, Any]) -> str:
        details = alert.get("details") or {}
        category = details.get("rule_category_label")
        if not category:
            return alert.get("message", "")

        rules = details.get("rules_violated") or details.get("reasons") or []
        protocol = alert.get("protocol") or "UNKNOWN"
        packet = details.get("latest_packet") or details.get("first_packet") or details.get("packet") or {}
        bus = packet.get("bus_num") or "unknown bus"
        has_timing = any(rule == "abnormal_goose_interval" for rule in rules)
        has_counter = any(rule in {"stNum_decreased", "smpCnt_decreased", "stNum_jump", "smpCnt_jump"} for rule in rules)

        if category == "Unexpected publisher":
            if has_timing and has_counter:
                return f"Unexpected {protocol} publisher with timing and counter anomalies on {bus}"
            if has_timing:
                return f"Unexpected {protocol} publisher with timing anomaly on {bus}"
            if has_counter:
                return f"Unexpected {protocol} publisher with counter anomaly on {bus}"
            return f"Unexpected {protocol} publisher on {bus}"
        if category == "Publisher MAC mismatch":
            return f"{protocol} publisher MAC mismatch on {bus}"
        if category == "Counter and timing anomaly" or (has_counter and has_timing):
            return f"{protocol} counter and timing anomaly on {bus}"
        if category in {"Counter anomaly", "GOOSE counter anomaly", "SV counter anomaly"}:
            return f"{protocol} counter anomaly on {bus}"
        if category == "Timing anomaly":
            return f"{protocol} timing anomaly on {bus}"
        return alert.get("message", "")

    def _prepare_group_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        grouped = dict(details)
        packet = grouped.get("packet")
        grouped.setdefault("first_packet", packet)
        grouped.setdefault("latest_packet", packet)
        grouped.setdefault("evidence_packets", [packet] if packet else [])
        if isinstance(packet, dict) and packet.get("index") is not None:
            grouped.setdefault("packet_indexes_sample", [packet["index"]])
        else:
            grouped.setdefault("packet_indexes_sample", [])
        return grouped

    def _fallback_group_key(self, alert: Dict[str, Any]) -> str:
        details = alert.get("details") or {}
        packet = details.get("packet") or {}
        rules = ",".join(sorted(details.get("rules_violated") or details.get("reasons") or []))
        identity = packet.get("gocbRef") or packet.get("svID") or packet.get("src_mac") or "unknown"
        return "|".join([
            alert.get("source", "unknown"),
            alert.get("protocol", "UNKNOWN"),
            rules,
            str(packet.get("bus_num") or "unknown"),
            str(identity),
            str(packet.get("src_mac") or "unknown"),
        ])

    def _update_incident(self, alert: Dict[str, Any]) -> None:
        for incident in self.state["incidents"]:
            if incident.get("alert_id") == alert.get("id"):
                incident["timestamp"] = alert.get("last_seen", alert.get("timestamp"))
                incident["severity"] = alert.get("severity", incident.get("severity"))
                incident["occurrence_count"] = alert.get("occurrence_count", incident.get("occurrence_count", 1))
                incident["message"] = f"{alert['protocol']} alert from {alert['source']}: {alert['message']}"
                return

    def _max_severity(self, current: str, incoming: str) -> str:
        order = ["info", "low", "medium", "high", "critical"]
        current_index = order.index(current) if current in order else 1
        incoming_index = order.index(incoming) if incoming in order else 1
        return order[max(current_index, incoming_index)]

    def bump_rule_evaluated(self) -> None:
        self.state["stats"]["rule_evaluated"] += 1

    def bump_ml_evaluated(self) -> None:
        self.state["stats"]["ml_evaluated"] += 1

    def _update_capture_span(self, timestamp: Any) -> None:
        try:
            ts = float(timestamp)
        except Exception:
            return
        stats = self.state["stats"]
        start = stats.get("capture_start_ts")
        end = stats.get("capture_end_ts")
        stats["capture_start_ts"] = ts if start is None else min(float(start), ts)
        stats["capture_end_ts"] = ts if end is None else max(float(end), ts)
        stats["capture_duration_seconds"] = round(stats["capture_end_ts"] - stats["capture_start_ts"], 6)
