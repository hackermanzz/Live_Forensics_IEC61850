from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from time import perf_counter
from typing import Any, Callable, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "rb engine"))

from packet_reader import is_goose_or_sv, iter_pcap, packet_protocol
from rule_engine import check_rules
from state_manager import StateManager

PARSER_PATH = ROOT_DIR / "rb engine" / "parser.py"
PARSER_SPEC = importlib.util.spec_from_file_location("rb_engine_parser", PARSER_PATH)
if PARSER_SPEC is None or PARSER_SPEC.loader is None:
    raise ImportError(f"Unable to load parser module from {PARSER_PATH}")
RB_ENGINE_PARSER = importlib.util.module_from_spec(PARSER_SPEC)
PARSER_SPEC.loader.exec_module(RB_ENGINE_PARSER)
parse_packet = RB_ENGINE_PARSER.parse_packet

from live_platform.detectors import MLDetector
from live_platform.ml_features import LiveMLFeatureBuilder
from live_platform.storage import LiveStore


PACKET_BATCH_SIZE = 500

SEVERITY_POINTS = {
    "info": 0,
    "low": 10,
    "medium": 35,
    "high": 70,
    "critical": 95,
}

RULE_LABELS = {
    "unknown_gocbRef": "Unknown GOOSE control block",
    "unknown_svID": "Unknown SV stream ID",
    "src_mac_mismatch": "GOOSE source MAC mismatch",
    "sv_src_mac_mismatch": "SV source MAC mismatch",
    "sv_publisher_mac_mismatch": "SV publisher MAC mismatch",
    "bus_mac_mismatch": "Bus MAC mismatch",
    "stNum_decreased": "GOOSE stNum decreased",
    "smpCnt_decreased": "SV sample counter decreased",
    "stNum_jump": "GOOSE stNum jump",
    "smpCnt_jump": "SV sample counter jump",
    "abnormal_goose_interval": "GOOSE timing anomaly",
}


def load_config(path: Any) -> Dict[str, Any]:
    import yaml

    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    return value


def feature_summary(feature: Dict[str, Any]) -> Dict[str, Any]:
    interesting = [
        "index",
        "timestamp",
        "protocol",
        "src_mac",
        "dst_mac",
        "src_ip",
        "dst_ip",
        "eth_type",
        "pkt_len",
        "bus_num",
        "gocbRef",
        "stNum",
        "sqNum",
        "svID",
        "smpCnt",
        "confRev",
        "breaker_signal",
        "breaker_status",
        "phaseA_voltage",
        "phaseB_voltage",
        "phaseC_voltage",
        "phaseA_current",
        "phaseB_current",
        "phaseC_current",
        "time_interval",
        "timing_rolling_std",
        "timing_cv",
        "stNum_cumulative_avg_diff",
        "stNum_deviation_from_median",
        "Correlation_Mismatch",
        "sv_i_max",
        "sv_v_max",
        # SV stream features — what the SV detector actually decides on, so an
        # SV alert's evidence blob shows WHY it fired.
        "noASDU",
        "smpcnt_delta",
        "smpcnt_back",
        "smpcnt_delta_roll_std",
        "dt",
        "dt_roll_med",
        "dt_ratio",
    ]
    return json_safe({key: feature.get(key) for key in interesting if key in feature})


class DetectionPipeline:
    def __init__(
        self,
        config_path: Any,
        store: LiveStore,
        ml_detector: Optional[MLDetector] = None,
    ) -> None:
        self.config_path = str(config_path)
        self.config = load_config(config_path)
        self.state = StateManager(self.config)
        self.store = store
        self.ml_detector = ml_detector or MLDetector()
        self.ml_feature_builder = LiveMLFeatureBuilder()

    def process_scapy_packet(self, scapy_pkt: Any, index: int, ts: Any, capture_source: str = "live") -> List[Dict[str, Any]]:
        started = perf_counter()
        feature = parse_packet(scapy_pkt, index, ts)
        self._record_timing("parse_packet", started)

        started = perf_counter()
        features = self._expand_sv_packet_features(feature)
        self._record_timing("expand_sv_features", started)

        alerts: List[Dict[str, Any]] = []
        for item in features:
            alerts.extend(self.process_feature(item, capture_source=capture_source))
        return alerts

    def process_scapy_packets_batch(self, packet_items: List[tuple[Any, int, Any, str]]) -> List[Dict[str, Any]]:
        features: List[Dict[str, Any]] = []
        for scapy_pkt, index, ts, capture_source in packet_items:
            started = perf_counter()
            feature = parse_packet(scapy_pkt, index, ts)
            self._record_timing("parse_packet", started)

            started = perf_counter()
            for item in self._expand_sv_packet_features(feature):
                item["_capture_source"] = capture_source
                features.append(item)
            self._record_timing("expand_sv_features", started)

        return self._process_features_batch(features)

    def process_feature(self, feature: Dict[str, Any], capture_source: str = "live") -> List[Dict[str, Any]]:
        item = dict(feature)
        item["_capture_source"] = capture_source
        return self._process_features_batch([item])

    def _process_features_batch(self, features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        pending_ml: List[tuple[Dict[str, Any], str]] = []
        packets_to_store: List[Dict[str, Any]] = []

        for feature in features:
            capture_source = str(feature.pop("_capture_source", "live"))
            self.store.bump_rule_evaluated()

            started = perf_counter()
            result = check_rules(feature, self.state)
            self._record_timing("rule_check", started)

            if "excluded_bus" in (result.get("reasons") or []):
                continue

            started = perf_counter()
            self._update_protocol_state(feature)
            self._record_timing("state_update", started)

            started = perf_counter()
            ml_feature = self.ml_feature_builder.enrich(feature)
            self._record_timing("ml_feature_enrich", started)

            started = perf_counter()
            packet = feature_summary(feature)
            packet["capture_source"] = capture_source
            packet["received_at"] = datetime.now(timezone.utc).isoformat()
            packets_to_store.append(packet)
            self._record_timing("store_packet", started)

            if result.get("rule_violation"):
                started = perf_counter()
                alerts.append(self._rule_alert(feature, result, capture_source))
                self._record_timing("build_rule_alert", started)
            elif feature.get("protocol") in {"GOOSE", "SV"}:
                self.store.bump_ml_evaluated()
                pending_ml.append((ml_feature, capture_source))

        if pending_ml:
            ml_features = [feature for feature, _ in pending_ml]
            started = perf_counter()
            if hasattr(self.ml_detector, "predict_batch"):
                ml_results = self.ml_detector.predict_batch(ml_features)
            else:
                ml_results = [self.ml_detector.predict(feature) for feature in ml_features]
            self._record_timing("ml_predict", started, count=len(pending_ml))

            for (ml_feature, capture_source), ml_result in zip(pending_ml, ml_results):
                if ml_result.get("is_anomaly"):
                    started = perf_counter()
                    alerts.append(self._ml_alert(ml_feature, ml_result, capture_source))
                    self._record_timing("build_ml_alert", started)

        if packets_to_store:
            started = perf_counter()
            self.store.add_packets(packets_to_store, update_ied=True)
            self._record_timing("store_packet_batch", started, count=len(packets_to_store))

        started = perf_counter()
        saved_alerts = [self.store.add_alert(alert) for alert in alerts]
        if alerts:
            self._record_timing("store_alerts", started, count=len(alerts))
        return saved_alerts

    def _expand_sv_packet_features(self, feature: Dict[str, Any]) -> List[Dict[str, Any]]:
        if feature.get("protocol") != "SV":
            return [feature]

        asdus = feature.get("sv_asdus") or []
        if not asdus:
            return [feature]

        expanded: List[Dict[str, Any]] = []
        for asdu in asdus:
            item = dict(feature)
            item.update(asdu)
            item["svID"] = asdu.get("svID") or feature.get("svID")
            item["smpCnt"] = asdu.get("smpCnt") if asdu.get("smpCnt") is not None else feature.get("smpCnt")
            item["confRev"] = asdu.get("confRev") if asdu.get("confRev") is not None else feature.get("confRev")
            item["phaseA_voltage"] = asdu.get("phaseA_voltage")
            item["phaseB_voltage"] = asdu.get("phaseB_voltage")
            item["phaseC_voltage"] = asdu.get("phaseC_voltage")
            item["phaseA_current"] = asdu.get("phaseA_current")
            item["phaseB_current"] = asdu.get("phaseB_current")
            item["phaseC_current"] = asdu.get("phaseC_current")
            expanded.append(item)
        return expanded

    def replay_file(
        self,
        pcap_path: Any,
        limit: Optional[int] = None,
        cancel_event: Optional[Event] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        alerts: List[Dict[str, Any]] = []
        count = 0
        total_count = 0
        skipped_count = 0
        goose_packet_count = 0
        sv_packet_count = 0
        cancelled = False
        detection_count = 0
        alert_ids_before = {alert.get("id") for alert in self.store.alerts()}
        stats = self.store.state["stats"]
        rule_evaluated_before = stats.get("rule_evaluated", 0)
        ml_evaluated_before = stats.get("ml_evaluated", 0)
        started_at = datetime.now(timezone.utc).isoformat()
        replay_started = perf_counter()
        packet_batch: List[tuple[Any, int, Any, str]] = []
        capture_source = Path(pcap_path).name

        def report_progress() -> None:
            if progress_callback is None:
                return
            progress_callback({
                "filename": capture_source,
                "packets_processed": count,
                "total_packets_seen": total_count,
                "skipped_packets": skipped_count,
                "goose_packets": goose_packet_count,
                "sv_packets": sv_packet_count,
                "analysis_rows": self.store.state["stats"].get("total_packets", 0),
                "detections_created": detection_count,
                "elapsed_seconds": round(perf_counter() - replay_started, 6),
            })

        def flush_batch() -> None:
            nonlocal detection_count
            if not packet_batch:
                return
            packet_alerts = self.process_scapy_packets_batch(packet_batch)
            if packet_alerts:
                detection_count += len(packet_alerts)
                alerts.extend(packet_alerts)
            packet_batch.clear()
            report_progress()

        for idx, ts, scapy_pkt in iter_pcap(str(pcap_path)):
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            total_count += 1
            if not is_goose_or_sv(scapy_pkt):
                skipped_count += 1
                if total_count % PACKET_BATCH_SIZE == 0:
                    report_progress()
                continue
            protocol = packet_protocol(scapy_pkt)
            if protocol == "GOOSE":
                goose_packet_count += 1
            elif protocol == "SV":
                sv_packet_count += 1
            packet_batch.append((scapy_pkt, idx, ts, capture_source))
            count += 1
            if len(packet_batch) >= PACKET_BATCH_SIZE:
                flush_batch()
            if limit is not None and count >= limit:
                break
        flush_batch()

        alert_ids_after = {alert.get("id") for alert in self.store.alerts()}
        unique_alerts_created = len(alert_ids_after - alert_ids_before)
        replay_elapsed = perf_counter() - replay_started
        rule_evaluated = self.store.state["stats"].get("rule_evaluated", 0) - rule_evaluated_before
        ml_evaluated = self.store.state["stats"].get("ml_evaluated", 0) - ml_evaluated_before

        summary = {
            "filename": Path(pcap_path).name,
            "engine": "rule_engine_then_protocol_ensembles",
            "rule_engine_config": self.config_path,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "packets_processed": count,
            "total_packets_seen": total_count,
            "skipped_packets": skipped_count,
            "goose_packets": goose_packet_count,
            "sv_packets": sv_packet_count,
            "packet_filter": "GOOSE/SV only",
            "cancelled": cancelled,
            "capture_start_ts": self.store.state["stats"].get("capture_start_ts"),
            "capture_end_ts": self.store.state["stats"].get("capture_end_ts"),
            "capture_duration_seconds": self.store.state["stats"].get("capture_duration_seconds"),
            "detections_created": detection_count,
            "alerts_created": unique_alerts_created,
            "grouped_alerts_touched": len({alert.get("id") for alert in alerts}),
            "processing_duration_seconds": round(replay_elapsed, 6),
            "packets_per_second": round(count / replay_elapsed, 2) if replay_elapsed > 0 else 0.0,
            "rule_evaluated": rule_evaluated,
            "ml_evaluated": ml_evaluated,
            "risk_score": self.risk_score(),
        }
        self.store.record_timing("replay_total", replay_elapsed)
        self.store.add_replay(summary)
        self.store.save()
        return {"alerts": alerts, "summary": summary}

    def risk_score(self) -> Dict[str, Any]:
        alerts = self.store.alerts()
        if not alerts:
            return {"score": 0, "label": "Low", "reason": "No alerts recorded"}

        recent = alerts[:50]
        points = sum(SEVERITY_POINTS.get(item.get("severity", "low"), 10) for item in recent)
        score = min(100, round(points / max(len(recent), 1)))
        if any(item.get("severity") in {"critical", "high"} for item in recent[:10]):
            score = max(score, 70)

        if score >= 75:
            label = "High"
        elif score >= 40:
            label = "Medium"
        else:
            label = "Low"
        return {"score": score, "label": label, "reason": f"Based on {len(recent)} most recent alerts"}

    def _rule_alert(self, feature: Dict[str, Any], result: Dict[str, Any], capture_source: str) -> Dict[str, Any]:
        reasons = result.get("reasons", [])
        packet = feature_summary(feature)
        category = self._rule_category(feature, reasons)
        return {
            "source": "rule_engine",
            "protocol": feature.get("protocol") or "UNKNOWN",
            "severity": result.get("severity", "low"),
            "message": category["message"],
            "group_key": self._group_key("rule_engine", feature, reasons, capture_source, category["id"]),
            "details": {
                "capture_source": capture_source,
                "rule_category": category["id"],
                "rule_category_label": category["label"],
                "rules_violated": reasons,
                "rule_labels": self._rule_labels(reasons),
                "expected_mac": self._expected_mac(feature),
                "explanation": self._rule_explanation(feature, reasons),
                "recommended_action": self._recommended_action(reasons),
                "packet": packet,
            },
        }

    def _ml_alert(self, feature: Dict[str, Any], result: Dict[str, Any], capture_source: str) -> Dict[str, Any]:
        return {
            "source": "ml_model",
            "protocol": feature.get("protocol") or "UNKNOWN",
            "severity": result.get("severity", "medium"),
            "message": result.get("message", "ML anomaly detected"),
            "group_key": self._group_key("ml_model", feature, [result.get("label", "unknown")], capture_source),
            "details": {
                "capture_source": capture_source,
                "model_label": result.get("label"),
                "confidence": result.get("confidence"),
                "model_details": json_safe(result.get("details", {})),
                "packet": feature_summary(feature),
            },
        }

    def ml_status(self) -> Dict[str, Any]:
        if hasattr(self.ml_detector, "status"):
            return self.ml_detector.status()
        return {"mode": "custom_detector", "ready": True}

    def reset_runtime_state(self) -> None:
        self.state.last_goose.clear()
        self.state.last_sv.clear()
        self.ml_feature_builder.reset()

    def _update_protocol_state(self, feature: Dict[str, Any]) -> None:
        if feature.get("protocol") == "GOOSE":
            self.state.update_goose(
                feature.get("gocbRef"),
                feature.get("stNum"),
                feature.get("sqNum"),
                feature.get("timestamp"),
                feature.get("src_mac"),
            )
        elif feature.get("protocol") == "SV":
            self.state.update_sv(
                feature.get("svID"),
                feature.get("smpCnt"),
                feature.get("timestamp"),
                feature.get("src_mac"),
            )

    def _group_key(
        self,
        source: str,
        feature: Dict[str, Any],
        reasons: List[str],
        capture_source: str,
        category: Optional[str] = None,
    ) -> str:
        identity = feature.get("gocbRef") or feature.get("svID") or "unknown"
        cause = category or ",".join(sorted(str(reason) for reason in reasons))
        return "|".join([
            capture_source,
            source,
            feature.get("protocol") or "UNKNOWN",
            cause,
            str(feature.get("bus_num") or "unknown"),
            str(identity),
            str(feature.get("src_mac") or "unknown").lower(),
        ])

    def _rule_message(self, feature: Dict[str, Any], reasons: List[str]) -> str:
        return self._rule_category(feature, reasons)["message"]

    def _rule_category(self, feature: Dict[str, Any], reasons: List[str]) -> Dict[str, str]:
        protocol = feature.get("protocol") or "UNKNOWN"
        bus_num = feature.get("bus_num") or "unknown bus"
        has_mac_issue = any(reason in {"src_mac_mismatch", "sv_src_mac_mismatch", "sv_publisher_mac_mismatch", "bus_mac_mismatch"} for reason in reasons)
        has_timing_issue = "abnormal_goose_interval" in reasons
        has_counter_issue = any(reason in {"stNum_decreased", "smpCnt_decreased", "stNum_jump", "smpCnt_jump"} for reason in reasons)
        has_unknown_id = "unknown_gocbRef" in reasons or "unknown_svID" in reasons
        if has_unknown_id and has_mac_issue:
            return {
                "id": "unexpected_publisher",
                "label": "Unexpected publisher",
                "message": f"Unexpected {protocol} publisher on {bus_num}",
            }
        if has_mac_issue:
            return {
                "id": "publisher_mac_mismatch",
                "label": "Publisher MAC mismatch",
                "message": f"{protocol} publisher MAC mismatch on {bus_num}",
            }
        if "stNum_decreased" in reasons:
            return {
                "id": "goose_counter_replay",
                "label": "GOOSE counter anomaly",
                "message": f"{protocol} stNum decreased on {bus_num}",
            }
        if "smpCnt_decreased" in reasons:
            return {
                "id": "sv_counter_replay",
                "label": "SV counter anomaly",
                "message": f"{protocol} sample counter decreased on {bus_num}",
            }
        if has_counter_issue:
            return {
                "id": "counter_anomaly",
                "label": "Counter anomaly",
                "message": f"{protocol} counter anomaly on {bus_num}",
            }
        if has_timing_issue:
            return {
                "id": "timing_anomaly",
                "label": "Timing anomaly",
                "message": f"{protocol} timing anomaly on {bus_num}",
            }
        if has_unknown_id:
            return {
                "id": "unknown_stream",
                "label": "Unknown stream ID",
                "message": f"Unknown {protocol} stream on {bus_num}",
            }
        return {
            "id": "rule_violation",
            "label": "Rule violation",
            "message": f"{protocol} rule violation on {bus_num}",
        }

    def _rule_labels(self, reasons: List[str]) -> List[str]:
        return [RULE_LABELS.get(str(reason), str(reason)) for reason in reasons]

    def _expected_mac(self, feature: Dict[str, Any]) -> Optional[str]:
        if feature.get("protocol") == "GOOSE":
            return self.config.get("gocbref_to_mac", {}).get(feature.get("gocbRef"))
        if feature.get("protocol") == "SV":
            publisher_macs = [str(mac) for mac in self.config.get("sv_publisher_macs", [])]
            if publisher_macs:
                return publisher_macs[0]
            return self.config.get("svid_to_mac", {}).get(feature.get("svID"))
        return None

    def _rule_explanation(self, feature: Dict[str, Any], reasons: List[str]) -> str:
        protocol = feature.get("protocol") or "UNKNOWN"
        bus_num = feature.get("bus_num") or "unknown bus"
        src_mac = feature.get("src_mac") or "unknown source"
        expected_mac = self._expected_mac(feature)
        identity = feature.get("gocbRef") or feature.get("svID") or "unknown publisher"
        has_unknown_id = "unknown_gocbRef" in reasons or "unknown_svID" in reasons
        has_mac_issue = any(reason in {"src_mac_mismatch", "sv_src_mac_mismatch", "sv_publisher_mac_mismatch", "bus_mac_mismatch"} for reason in reasons)
        if has_unknown_id and has_mac_issue:
            return f"{protocol} traffic on {bus_num} used an unknown stream/control-block identity ({identity}) and came from {src_mac}. Treat this as an unexpected publisher until the mapping is verified."
        if any(reason in {"src_mac_mismatch", "sv_src_mac_mismatch", "sv_publisher_mac_mismatch", "bus_mac_mismatch"} for reason in reasons):
            return f"{protocol} traffic for {identity} on {bus_num} came from {src_mac}, but the configured expected MAC is {expected_mac or 'not configured'}."
        if "stNum_decreased" in reasons:
            return f"{protocol} state number decreased for {identity} on {bus_num}, which may indicate replayed or out-of-order GOOSE traffic."
        if "smpCnt_decreased" in reasons:
            return f"{protocol} sample counter decreased for {identity} on {bus_num}, which may indicate replayed or out-of-order SV traffic."
        if "abnormal_goose_interval" in reasons:
            return f"{protocol} traffic interval for {identity} on {bus_num} exceeded the configured timing baseline."
        return f"{protocol} traffic for {identity} on {bus_num} violated one or more configured rules: {', '.join(reasons) or 'unknown'}."

    def _recommended_action(self, reasons: List[str]) -> str:
        if any(reason in {"src_mac_mismatch", "sv_src_mac_mismatch", "sv_publisher_mac_mismatch", "bus_mac_mismatch"} for reason in reasons):
            return "Verify the expected publisher MAC mapping, check for spoofing or unauthorized publisher traffic, and compare with switch port/TAP observations."
        if "stNum_decreased" in reasons or "smpCnt_decreased" in reasons:
            return "Check for replay, duplicate capture paths, publisher restart behavior, or out-of-order packet delivery."
        if "abnormal_goose_interval" in reasons:
            return "Compare the publisher timing with normal process behavior and inspect the network path for delay, loss, or publisher instability."
        return "Review the packet evidence and compare it against the configured IED/bus mapping."

    def _record_timing(self, name: str, started: float, count: int = 1) -> None:
        self.store.record_timing(name, perf_counter() - started, count=count)
