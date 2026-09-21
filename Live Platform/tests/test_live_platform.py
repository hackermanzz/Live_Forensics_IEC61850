import sys
from pathlib import Path
import tempfile
import os
import threading
import pytest
import importlib.util

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("GOOSE_RF_MODEL", str(Path(tempfile.gettempdir()) / "missing_rf_goose_detector.joblib"))
os.environ.setdefault("GOOSE_XGB_MODEL", str(Path(tempfile.gettempdir()) / "missing_xgb_goose_detector.joblib"))
os.environ.setdefault("SV_RF_MODEL", str(Path(tempfile.gettempdir()) / "missing_rf_sv_detector.joblib"))
os.environ.setdefault("SV_XGB_MODEL", str(Path(tempfile.gettempdir()) / "missing_xgb_sv_detector.joblib"))

from fastapi.testclient import TestClient
from live_platform.app import app


class FakeJoblibMember:
    def __init__(self, label):
        self.label = label

    def predict_one(self, features):
        return {
            "is_anomaly": True,
            "label": self.label,
            "confidence": 0.91,
        }


class FeatureNamedEstimator:
    feature_names_in_ = [
        "time_interval",
        "timing_rolling_std",
        "timing_cv",
        "stNum_cumulative_avg_diff",
        "stNum_deviation_from_median",
        "Correlation_Mismatch",
    ]
    classes_ = [0, 1]

    def predict(self, rows):
        assert list(rows.columns) == self.feature_names_in_
        assert rows.iloc[0]["stNum_deviation_from_median"] == 5.0
        return [1]

    def predict_proba(self, rows):
        assert list(rows.columns) == self.feature_names_in_
        return [[0.12, 0.88]]


class SvFeatureNamedEstimator:
    feature_names_in_ = ["sv_i_max", "sv_v_max"]
    classes_ = [0, 1]

    def predict(self, rows):
        assert list(rows.columns) == self.feature_names_in_
        assert rows.iloc[0]["sv_i_max"] == 8.0
        assert rows.iloc[0]["sv_v_max"] == 220.0
        return [1]

    def predict_proba(self, rows):
        assert list(rows.columns) == self.feature_names_in_
        return [[0.2, 0.8]]


def test_vlan_tagged_sv_packet_is_recognized():
    from scapy.all import Dot1Q, Ether, Raw
    from packet_reader import is_goose_or_sv

    parser_path = Path(__file__).resolve().parents[1] / "rb engine" / "parser.py"
    parser_spec = importlib.util.spec_from_file_location("rb_engine_parser", parser_path)
    assert parser_spec is not None and parser_spec.loader is not None
    parser_module = importlib.util.module_from_spec(parser_spec)
    parser_spec.loader.exec_module(parser_module)

    vlan_pkt = Ether(type=0x8100) / Dot1Q(vlan=1, type=0x88BA) / Raw(b"\x01\x02\x03")

    assert is_goose_or_sv(vlan_pkt) is True
    feature = parser_module.parse_packet(vlan_pkt, 1, 1.0)
    assert feature["protocol"] == "SV"


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["detection_pipeline"] == "rule_engine_then_protocol_ensembles"


def test_dashboard_pages_are_split_by_mode():
    client = TestClient(app)

    root = client.get("/", follow_redirects=False)
    assert root.status_code in {307, 308}
    assert root.headers["location"] == "/replay"

    replay = client.get("/replay")
    assert replay.status_code == 200
    assert "PCAP Replay Platform" in replay.text
    assert 'id="replayButton"' in replay.text
    assert 'id="replayHistory"' in replay.text
    assert "Protocol Traffic Summary" in replay.text
    assert "Filtered Traffic" in replay.text
    assert "Start Live</button>" not in replay.text
    assert "GOOSE/SV ensembles pending model files" not in replay.text
    assert "function mlStatusText" in replay.text

    live = client.get("/live")
    assert live.status_code == 200
    assert "Live Capture Platform" in live.text
    assert "Start Live" in live.text
    assert 'id="interfaceSelect"' in live.text
    assert 'id="manualInterface"' in live.text
    assert 'id="diagnosticButton"' in live.text
    assert 'id="replayButton"' not in live.text
    assert 'id="replayHistory"' not in live.text


def test_engine_status_endpoint_shows_rule_engine_enabled():
    client = TestClient(app)
    response = client.get("/api/engine-status")
    assert response.status_code == 200
    data = response.json()
    assert data["rule_engine"] == "enabled"
    assert data["replay_mode"] == "goose_sv_filtered_pcap_scan"
    assert "live_capture" in data
    assert data["pipeline"] == "rule_engine_then_protocol_ensembles"
    assert data["ml_status"]["mode"] == "protocol_ensembles"
    assert data["ml_status"]["artifact_format"] == "joblib"
    assert data["ml_status"]["protocols"]["GOOSE"]["expected_members"] == 2
    assert data["ml_status"]["protocols"]["SV"]["expected_members"] == 2
    assert len(data["ml_status"]["protocols"]["GOOSE"]["artifact_paths"]) == 2


def test_inventory_endpoint_returns_configured_ieds():
    client = TestClient(app)
    response = client.get("/api/inventory")
    assert response.status_code == 200
    data = response.json()
    assert "devices" in data
    assert any(device["bus"] == "bus1" for device in data["devices"])
    assert any(device["expected_mac"] == "b8:27:eb:c2:49:ab" for device in data["devices"])


def test_monitor_page_and_endpoint_return_ied_measurements_after_replay():
    client = TestClient(app)
    client.post("/api/clear")
    page = client.get("/monitor")
    assert page.status_code == 200

    pcap_path = Path(__file__).resolve().parents[1] / "pcaps" / "test_goose_sv_mid.pcapng"
    with pcap_path.open("rb") as handle:
        replay = client.post(
            "/api/replay-pcap?wait=true",
            files={"file": (pcap_path.name, handle, "application/octet-stream")},
        )
    assert replay.status_code == 200

    response = client.get("/api/ied-monitor")
    assert response.status_code == 200
    data = response.json()
    assert data["timeline"]["capture_duration_seconds"] is not None
    bus2 = next(device for device in data["devices"] if device["bus"] == "bus2")
    assert bus2["measurements"]["voltage"]["phaseA"] == 1077423.625
    assert bus2["measurements"]["current"]["phaseA"] == 2.151966094970703
    assert bus2["breaker_status"] in {"trip/open signal active", "normal/closed signal", "not observed"}


def test_replays_endpoint_returns_list():
    client = TestClient(app)
    response = client.get("/api/replays")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_live_control_endpoints():
    client = TestClient(app)
    interfaces = client.get("/api/live/interfaces")
    assert interfaces.status_code == 200
    assert "interfaces" in interfaces.json()

    start = client.post("/api/live/start", json={})
    assert start.status_code == 200
    assert start.json()["enabled"] is True
    assert start.json()["interface"] == "not_configured"
    assert start.json()["mode"] == "control_plane_ready"

    status = client.get("/api/live/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is True

    stop = client.post("/api/live/stop")
    assert stop.status_code == 200
    assert stop.json()["enabled"] is False

    diagnostic = client.post("/api/live/diagnostic", json={})
    assert diagnostic.status_code == 200
    assert diagnostic.json()["status"] == "not_started"
    assert diagnostic.json()["error"] == "interface_required"


def test_alerts_endpoint_returns_list():
    client = TestClient(app)
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_detection_ingest_endpoint_accepts_rule_engine_events():
    client = TestClient(app)
    client.post("/api/clear")
    response = client.post(
        "/api/ingest-detection",
        json={
            "source": "rule_engine",
            "protocol": "GOOSE",
            "severity": "high",
            "message": "Suspicious GOOSE sequence detected",
            "details": {"reason": "stNum_jump"},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "rule_engine"
    assert data["severity"] == "high"
    detail = client.get(f"/api/alerts/{data['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == data["id"]


def test_stats_endpoint_includes_risk_and_counts():
    client = TestClient(app)
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "risk" in data
    assert "alert_count" in data
    assert "processed_protocol_counts" in data
    assert set(data["processed_protocol_counts"]).issubset({"GOOSE", "SV"})
    assert data["filtered_traffic"]["filter"] == "GOOSE/SV only"


def test_performance_endpoint_returns_metrics_list():
    client = TestClient(app)
    response = client.get("/api/performance")
    assert response.status_code == 200
    assert "metrics" in response.json()


def test_clear_endpoint_resets_memory():
    client = TestClient(app)
    client.post(
        "/api/alerts",
        json={
            "source": "rule_engine",
            "protocol": "SV",
            "severity": "medium",
            "message": "temporary alert",
            "details": {},
        },
    )
    response = client.post("/api/clear")
    assert response.status_code == 200
    assert response.json()["alerts"] == []


def test_clear_endpoint_cancels_active_replay_jobs():
    from live_platform.app import replay_cancel_events, replay_futures, replay_jobs

    client = TestClient(app)
    job_id = "unit-clear-cancel"
    event = threading.Event()
    replay_jobs[job_id] = {
        "job_id": job_id,
        "filename": "unit.pcapng",
        "status": "running",
        "started_at": "unit",
        "finished_at": None,
        "summary": None,
        "error": None,
    }
    replay_cancel_events[job_id] = event
    replay_futures.pop(job_id, None)

    response = client.post("/api/clear")

    assert response.status_code == 200
    assert event.is_set()
    assert job_id in response.json()["cancelled_replay_jobs"]
    assert replay_jobs[job_id]["status"] == "cancel_requested"
    replay_jobs.pop(job_id, None)
    replay_cancel_events.pop(job_id, None)


def test_active_replay_job_endpoint_returns_running_job():
    from live_platform.app import replay_jobs

    client = TestClient(app)
    job_id = "unit-active-replay"
    replay_jobs[job_id] = {
        "job_id": job_id,
        "filename": "active.pcapng",
        "status": "running",
        "started_at": "2026-07-18T00:00:00+00:00",
        "finished_at": None,
        "summary": None,
        "error": None,
    }

    response = client.get("/api/replay-jobs/active")

    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    assert response.json()["filename"] == "active.pcapng"
    replay_jobs.pop(job_id, None)


def test_replay_endpoint_accepts_pcap_upload():
    client = TestClient(app)
    pcap_path = Path(__file__).resolve().parents[1] / "pcaps" / "test_goose_sv_mid.pcapng"
    with pcap_path.open("rb") as handle:
        response = client.post(
            "/api/replay-pcap?wait=true",
            files={"file": (pcap_path.name, handle, "application/octet-stream")},
        )
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert data["summary"]["total_packets_seen"] >= data["summary"]["packets_processed"]
    assert data["summary"]["packet_filter"] == "GOOSE/SV only"
    assert data["summary"]["cancelled"] is False


def test_pipeline_replay_can_be_cancelled_before_processing():
    from live_platform.storage import LiveStore
    from live_platform.pipeline import DetectionPipeline

    root = Path(__file__).resolve().parents[1]
    store = LiveStore(Path(tempfile.gettempdir()) / "cancelled_replay_test_state.json")
    store.clear()
    cancel_event = threading.Event()
    cancel_event.set()
    pipeline = DetectionPipeline(root / "live_platform" / "config_example.yml", store)
    result = pipeline.replay_file(root / "pcaps" / "test_goose_sv_mid.pcapng", cancel_event=cancel_event)

    assert result["summary"]["cancelled"] is True
    assert result["summary"]["packets_processed"] == 0
    assert result["summary"]["total_packets_seen"] == 0


def test_pcap_replay_emits_summary_alert_when_no_rule_violation():
    from live_platform.pcap_replay import PcapReplay

    replay = PcapReplay(str(Path(__file__).resolve().parents[1] / "rb engine" / "config_example.yml"))
    alerts = replay.replay_file(str(Path(__file__).resolve().parents[1] / "pcaps" / "test_goose_sv_mid.pcapng"), limit=10)
    assert len(alerts) >= 1


def test_lowdeltamismatch_replay_flags_goose_mac_mismatch():
    from live_platform.storage import LiveStore
    from live_platform.pipeline import DetectionPipeline

    root = Path(__file__).resolve().parents[1]
    store = LiveStore(Path(tempfile.gettempdir()) / "lowdeltamismatch_test_state.json")
    store.clear()
    pipeline = DetectionPipeline(root / "live_platform" / "config_example.yml", store)
    result = pipeline.replay_file(root / "pcaps" / "lowdeltamismatch.pcapng")

    assert result["summary"]["total_packets_seen"] == 22027
    assert result["summary"]["packets_processed"] == 20839
    assert result["summary"]["skipped_packets"] == 1188
    assert result["summary"]["detections_created"] >= 400
    assert result["summary"]["alerts_created"] < result["summary"]["detections_created"]
    grouped_alerts = store.alerts()
    assert len(grouped_alerts) == result["summary"]["alerts_created"]
    assert any(alert.get("occurrence_count", 0) >= 400 for alert in grouped_alerts)
    assert any(
        (alert["details"].get("first_packet", {}).get("index") == 12337
        or alert["details"].get("packet", {}).get("index") == 12337)
        and "src_mac_mismatch" in alert["details"].get("rules_violated", [])
        and "bus_mac_mismatch" in alert["details"].get("rules_violated", [])
        and alert["details"].get("explanation")
        and alert["details"].get("recommended_action")
        for alert in result["alerts"]
    )


def test_browser_replay_endpoint_uses_rule_engine_for_lowdeltamismatch():
    client = TestClient(app)
    client.post("/api/clear")
    pcap_path = Path(__file__).resolve().parents[1] / "pcaps" / "lowdeltamismatch.pcapng"
    with pcap_path.open("rb") as handle:
        response = client.post(
            "/api/replay-pcap?wait=true",
            files={"file": (pcap_path.name, handle, "application/octet-stream")},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["engine"] == "rule_engine_then_protocol_ensembles"
    assert data["summary"]["total_packets_seen"] == 22027
    assert data["summary"]["packets_processed"] == 20839
    assert data["summary"]["skipped_packets"] == 1188
    assert data["summary"]["detections_created"] >= 400
    assert data["summary"]["alerts_created"] < data["summary"]["detections_created"]
    stats = client.get("/api/stats").json()
    assert stats["alert_count"] == data["summary"]["alerts_created"]


def test_protocol_ensemble_runs_after_rules_pass():
    from live_platform.detectors import EnsembleDetector, ProtocolMLRouter
    from live_platform.pipeline import DetectionPipeline
    from live_platform.storage import LiveStore

    class FakeMember:
        def __init__(self, label):
            self.label = label

        def predict_one(self, features):
            return {
                "is_anomaly": True,
                "label": self.label,
                "confidence": 0.8,
            }

    root = Path(__file__).resolve().parents[1]
    store = LiveStore(Path(tempfile.gettempdir()) / "ensemble_test_state.json")
    store.clear()
    router = ProtocolMLRouter(
        goose_detector=EnsembleDetector("GOOSE", [FakeMember("goose_attack"), FakeMember("goose_attack")])
    )
    pipeline = DetectionPipeline(root / "live_platform" / "config_example.yml", store, ml_detector=router)
    alerts = pipeline.process_feature(
        {
            "index": 1,
            "timestamp": 1.0,
            "protocol": "GOOSE",
            "src_mac": "b8:27:eb:c2:49:ab",
            "dst_mac": "01:0c:cd:01:00:01",
            "gocbRef": "simpleIOGenericIO/LLN0$GO$gcbAnalogValues1",
            "stNum": 1,
            "sqNum": 1,
        },
        capture_source="unit",
    )

    assert len(alerts) == 1
    assert alerts[0]["source"] == "ml_model"
    assert alerts[0]["details"]["model_label"] == "goose_attack"
    assert alerts[0]["details"]["model_details"]["members_evaluated"] == 2


def test_rule_message_describes_combined_rule_causes():
    from live_platform.pipeline import DetectionPipeline
    from live_platform.storage import LiveStore

    root = Path(__file__).resolve().parents[1]
    store = LiveStore(Path(tempfile.gettempdir()) / "message_test_state.json")
    pipeline = DetectionPipeline(root / "live_platform" / "config_example.yml", store)

    assert pipeline._rule_message(
        {"protocol": "SV", "bus_num": "bus1"},
        ["unknown_svID", "bus_mac_mismatch"],
    ) == "Unexpected SV publisher on bus1"
    assert pipeline._rule_message(
        {"protocol": "SV", "bus_num": "bus1"},
        ["unknown_svID", "bus_mac_mismatch", "sv_publisher_mac_mismatch"],
    ) == "Unexpected SV publisher on bus1"
    assert pipeline._rule_message(
        {"protocol": "SV", "bus_num": "bus1"},
        ["unknown_svID", "bus_mac_mismatch", "sv_publisher_mac_mismatch", "smpCnt_decreased"],
    ) == "Unexpected SV publisher on bus1"


def test_grouped_rule_alerts_merge_rule_causes():
    from live_platform.storage import LiveStore

    store = LiveStore(Path(tempfile.gettempdir()) / "grouped_rule_merge_test_state.json")
    store.clear()
    base = {
        "source": "rule_engine",
        "protocol": "SV",
        "severity": "medium",
        "message": "Unexpected SV publisher on bus1",
        "group_key": "same-group",
        "details": {
            "rule_category_label": "Unexpected publisher",
            "rules_violated": ["unknown_svID", "bus_mac_mismatch"],
            "rule_labels": ["Unknown SV stream ID", "Bus MAC mismatch"],
            "packet": {"index": 1},
        },
    }
    store.add_alert(base)
    store.add_alert({
        **base,
        "message": "Unexpected SV publisher on bus1",
        "details": {
            **base["details"],
            "rules_violated": ["unknown_svID", "bus_mac_mismatch", "sv_publisher_mac_mismatch"],
            "rule_labels": ["Unknown SV stream ID", "Bus MAC mismatch", "SV publisher MAC mismatch"],
            "packet": {"index": 2},
        },
    })
    store.add_alert({
        **base,
        "message": "Unexpected SV publisher on bus1",
        "details": {
            **base["details"],
            "rules_violated": ["unknown_svID", "bus_mac_mismatch", "sv_publisher_mac_mismatch"],
            "rule_labels": ["Unknown SV stream ID", "Bus MAC mismatch", "SV publisher MAC mismatch"],
            "packet": {"index": 3, "bus_num": "bus1"},
        },
    })

    alert = store.alerts()[0]
    assert alert["occurrence_count"] == 3
    assert alert["message"] == "Unexpected SV publisher on bus1"
    assert alert["details"]["rules_violated"] == ["unknown_svID", "bus_mac_mismatch", "sv_publisher_mac_mismatch"]
    assert alert["details"]["rule_labels"] == [
        "Unknown SV stream ID",
        "Bus MAC mismatch",
        "SV publisher MAC mismatch",
    ]


def test_protocol_ensemble_loads_joblib_members(tmp_path):
    joblib = pytest.importorskip("joblib")

    from live_platform.detectors import EnsembleDetector

    first = tmp_path / "rf_goose_detector.joblib"
    second = tmp_path / "xgb_goose_detector.joblib"
    joblib.dump(FakeJoblibMember("joblib_goose_attack"), first)
    joblib.dump(FakeJoblibMember("joblib_goose_attack"), second)

    detector = EnsembleDetector.from_joblib_files("GOOSE", [first, second])
    status = detector.status()
    result = detector.predict({"protocol": "GOOSE"})

    assert status["ready"] is True
    assert status["loaded_members"] == 2
    assert result["is_anomaly"] is True
    assert result["label"] == "joblib_goose_attack"
    assert result["details"]["members_evaluated"] == 2


def test_joblib_estimator_receives_named_feature_matrix(tmp_path):
    joblib = pytest.importorskip("joblib")

    from live_platform.detectors import EnsembleDetector

    artifact = tmp_path / "rf_goose_detector.joblib"
    joblib.dump(FeatureNamedEstimator(), artifact)

    detector = EnsembleDetector.from_joblib_files("GOOSE", [artifact, None])
    result = detector.predict({
        "protocol": "GOOSE",
        "time_interval": 0.004,
        "timing_rolling_std": 0.001,
        "timing_cv": 0.2,
        "stNum_cumulative_avg_diff": 5.0,
        "stNum_deviation_from_median": 5.0,
        "Correlation_Mismatch": 0,
    })

    assert result["is_anomaly"] is True
    assert result["confidence"] == 0.88


def test_sv_joblib_estimator_receives_named_feature_matrix(tmp_path):
    joblib = pytest.importorskip("joblib")

    from live_platform.detectors import EnsembleDetector

    artifact = tmp_path / "rf_sv_detector.joblib"
    joblib.dump(SvFeatureNamedEstimator(), artifact)

    detector = EnsembleDetector.from_joblib_files("SV", [artifact, None])
    result = detector.predict({
        "protocol": "SV",
        "sv_i_max": 8.0,
        "sv_v_max": 220.0,
    })

    assert result["is_anomaly"] is True
    assert result["confidence"] == 0.8


def test_live_goose_feature_builder_adds_model_fields():
    from live_platform.ml_features import LiveMLFeatureBuilder

    builder = LiveMLFeatureBuilder()
    first = builder.enrich({
        "protocol": "GOOSE",
        "timestamp": 10.0,
        "gocbRef": "publisher-a",
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "stNum": 10,
    })
    second = builder.enrich({
        "protocol": "GOOSE",
        "timestamp": 10.02,
        "gocbRef": "publisher-a",
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "stNum": 15,
    })

    assert first["time_interval"] == 0.0
    assert round(second["time_interval"], 2) == 0.02
    assert second["stNum_cumulative_avg_diff"] == 5.0
    assert second["stNum_deviation_from_median"] == 5.0
    assert second["Correlation_Mismatch"] == 0


def test_live_sv_feature_builder_adds_model_fields():
    from live_platform.ml_features import LiveMLFeatureBuilder

    builder = LiveMLFeatureBuilder()
    enriched = builder.enrich({
        "protocol": "SV",
        "phaseA_voltage": 100.0,
        "phaseB_voltage": -220.0,
        "phaseC_voltage": 180.0,
        "phaseA_current": 2.0,
        "phaseB_current": -8.0,
        "phaseC_current": 5.0,
    })

    assert enriched["sv_v_max"] == 220.0
    assert enriched["sv_i_max"] == 8.0
