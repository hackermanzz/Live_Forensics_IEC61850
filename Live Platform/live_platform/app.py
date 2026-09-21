from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from typing import Any, List, Optional, Union
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
import os
import sys
import uuid

ROOT_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT_DIR / "templates"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "rb engine"))

from live_platform.pipeline import DetectionPipeline
from live_platform.storage import LiveStore
from live_platform.live_capture import LiveCaptureController
from live_platform.detectors import ProtocolMLRouter

app = FastAPI(title="Live Forensic Platform")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AlertPayload(BaseModel):
    source: str
    protocol: str
    severity: str
    message: str
    details: Optional[dict] = None


class DetectionIngestPayload(BaseModel):
    source: str
    protocol: str
    severity: str
    message: str
    details: Optional[dict] = None


class LiveStartPayload(BaseModel):
    interface: Optional[str] = None


class LiveDiagnosticPayload(BaseModel):
    interface: Optional[str] = None
    duration_seconds: Optional[float] = 5.0


STATE_PATH = ROOT_DIR / "live_platform" / "data" / "live_state.json"
CONFIG_PATH = ROOT_DIR / "live_platform" / "config_example.yml"
MODEL_DIR = ROOT_DIR / "models"
store = LiveStore(STATE_PATH)
pipeline = DetectionPipeline(CONFIG_PATH, store, ml_detector=ProtocolMLRouter.from_joblib_files(
    goose_paths=[
        os.getenv("GOOSE_RF_MODEL") or os.getenv("GOOSE_MODEL_1") or MODEL_DIR / "rf_goose_detector.joblib",
        os.getenv("GOOSE_XGB_MODEL") or os.getenv("GOOSE_MODEL_2") or MODEL_DIR / "xgb_goose_detector.joblib",
    ],
    sv_paths=[
        os.getenv("SV_RF_MODEL") or os.getenv("SV_MODEL_1") or MODEL_DIR / "rf_sv_detector.joblib",
        os.getenv("SV_XGB_MODEL") or os.getenv("SV_MODEL_2") or MODEL_DIR / "xgb_sv_detector.joblib",
    ],
))
live_capture = LiveCaptureController()
replay_executor = ThreadPoolExecutor(max_workers=1)
replay_jobs: dict[str, dict[str, Any]] = {}
replay_cancel_events: dict[str, threading.Event] = {}
replay_futures: dict[str, Any] = {}


class _StoreBackedList:
    def __init__(self, key: str) -> None:
        self.key = key

    def __len__(self) -> int:
        return len(store.state[self.key])

    def insert(self, index: int, value: dict) -> None:
        if self.key == "alerts":
            store.add_alert(value)
        else:
            store.state[self.key].insert(index, value)
        store.save()


alerts: List[dict] = _StoreBackedList("alerts")  # type: ignore[assignment]
incidents: List[dict] = _StoreBackedList("incidents")  # type: ignore[assignment]


@app.get("/")
async def index(request: Request):
    return RedirectResponse(url="/replay")


@app.get("/replay", response_class=HTMLResponse)
async def replay_page(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "page_mode": "replay",
            "page_title": "PCAP Replay Platform",
            "page_description": "Replay uploaded captures through rule-based and ML detection.",
        },
    )


@app.get("/live", response_class=HTMLResponse)
async def live_page(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "page_mode": "live",
            "page_title": "Live Capture Platform",
            "page_description": "Monitor live GOOSE/SV traffic from a selected interface.",
        },
    )


@app.get("/monitor", response_class=HTMLResponse)
async def monitor(request: Request):
    return templates.TemplateResponse(request, "monitor.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_pipeline": "rule_engine_then_protocol_ensembles",
        "rule_engine_config": str(CONFIG_PATH),
    }


@app.get("/api/engine-status")
def engine_status():
    return {
        "pipeline": "rule_engine_then_protocol_ensembles",
        "rule_engine": "enabled",
        "ml_adapter": "goose_sv_joblib_protocol_ensembles",
        "ml_status": pipeline.ml_status(),
        "config": str(CONFIG_PATH),
        "replay_mode": "goose_sv_filtered_pcap_scan",
        "live_capture": live_capture.status(),
    }


@app.get("/api/alerts")
def get_alerts():
    return store.alerts()


@app.get("/api/incidents")
def get_incidents():
    return store.incidents()


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: int):
    alert = store.get_alert(alert_id)
    if alert is None:
        return {"error": "alert_not_found", "alert_id": alert_id}
    return alert


@app.get("/api/replays")
def get_replays():
    return store.snapshot()["stats"].get("replays", [])


@app.get("/api/replay-jobs/active")
def get_active_replay_job():
    active_statuses = {"queued", "running", "cancel_requested"}
    for job in sorted(replay_jobs.values(), key=lambda item: item.get("started_at") or "", reverse=True):
        if job.get("status") in active_statuses:
            return job
    return {"status": "none", "job": None}


@app.get("/api/replay-jobs/{job_id}")
def get_replay_job(job_id: str):
    return replay_jobs.get(job_id) or {"job_id": job_id, "status": "not_found"}


@app.post("/api/replay-jobs/{job_id}/cancel")
def cancel_replay_job(job_id: str):
    job = replay_jobs.get(job_id)
    if job is None:
        return {"job_id": job_id, "status": "not_found"}
    if job.get("status") not in {"queued", "running", "cancel_requested"}:
        return job

    event = replay_cancel_events.get(job_id)
    if event is not None:
        event.set()

    future = replay_futures.get(job_id)
    if future is not None and future.cancel():
        job.update({
            "status": "cancelled",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "message": "Replay was cancelled before it started.",
        })
    else:
        job.update({
            "status": "cancel_requested",
            "message": "Replay cancellation requested.",
        })
    return job


@app.post("/api/replay-jobs/cancel-active")
def cancel_active_replay_jobs():
    return _cancel_active_replay_jobs(wait_for_stop=False)


@app.get("/api/inventory")
def get_inventory():
    return {"devices": _build_inventory()}


@app.get("/api/ied-monitor")
def get_ied_monitor():
    return {
        "devices": _build_monitor_devices(),
        "timeline": _capture_timeline(),
    }


@app.get("/api/live/status")
def live_status():
    return live_capture.status()


@app.get("/api/live/interfaces")
def live_interfaces():
    return live_capture.interfaces()


@app.post("/api/live/start")
def live_start(payload: Optional[LiveStartPayload] = None):
    interface = payload.interface if payload else None
    return live_capture.start(interface, pipeline.process_scapy_packet, pipeline.process_scapy_packets_batch)


@app.post("/api/live/stop")
def live_stop():
    return live_capture.stop()


@app.post("/api/live/diagnostic")
async def live_diagnostic(payload: Optional[LiveDiagnosticPayload] = None):
    interface = payload.interface if payload else None
    duration_seconds = payload.duration_seconds if payload else 5.0
    return await run_in_threadpool(live_capture.diagnostic, interface, duration_seconds or 5.0)


@app.get("/api/stats")
def get_stats():
    snapshot = store.snapshot()
    live_status = live_capture.status()
    protocol_counts = snapshot["stats"].get("protocol_counts", {})
    processed_protocol_counts = {
        protocol: protocol_counts.get(protocol, 0)
        for protocol in ("GOOSE", "SV")
        if protocol_counts.get(protocol, 0)
    }
    latest_replay = (snapshot["stats"].get("replays") or [None])[0] or {}
    active_replay = next(
        (
            job
            for job in replay_jobs.values()
            if job.get("status") in {"queued", "running", "cancel_requested"} and job.get("progress")
        ),
        None,
    )
    replay_counts = active_replay.get("progress") if active_replay else latest_replay
    filtered_traffic = {
        "pcap_skipped_packets": replay_counts.get("skipped_packets", 0),
        "pcap_total_packets_seen": replay_counts.get("total_packets_seen", 0),
        "pcap_goose_packets": replay_counts.get("goose_packets", 0),
        "pcap_sv_packets": replay_counts.get("sv_packets", 0),
        "analysis_rows": snapshot["stats"].get("total_packets", 0),
        "excluded_buses": sorted(pipeline.config.get("excluded_buses", []), key=_bus_sort_key),
        "live_ignored_packets": live_status.get("ignored_packet_count", 0),
        "filter": "GOOSE/SV only",
    }
    return {
        "stats": snapshot["stats"],
        "live_capture": live_status,
        "processed_protocol_counts": processed_protocol_counts,
        "filtered_traffic": filtered_traffic,
        "risk": pipeline.risk_score(),
        "alert_count": len(snapshot["alerts"]),
        "incident_count": len(snapshot["incidents"]),
        "recent_packets": snapshot["packets"][:20],
    }


@app.get("/api/performance")
def get_performance():
    performance = store.snapshot()["stats"].get("performance", {})
    metrics = []
    for name, metric in performance.items():
        count = metric.get("count", 0)
        total_seconds = float(metric.get("total_seconds", 0.0))
        metrics.append({
            "name": name,
            "count": count,
            "total_seconds": round(total_seconds, 6),
            "avg_ms": round(float(metric.get("avg_seconds", 0.0)) * 1000, 4),
            "max_ms": round(float(metric.get("max_seconds", 0.0)) * 1000, 4),
            "percent": 0.0,
        })

    total = sum(item["total_seconds"] for item in metrics)
    if total > 0:
        for item in metrics:
            item["percent"] = round((item["total_seconds"] / total) * 100, 2)

    metrics.sort(key=lambda item: item["total_seconds"], reverse=True)
    return {"metrics": metrics}


def _build_inventory() -> List[dict[str, Any]]:
    cfg = pipeline.config
    snapshot = store.snapshot()
    packets = snapshot.get("packets", [])
    alerts_snapshot = snapshot.get("alerts", [])
    devices: List[dict[str, Any]] = []

    for bus, expected_mac in sorted(cfg.get("bus_to_mac", {}).items(), key=lambda item: _bus_sort_key(item[0])):
        gocb_refs = [ref for ref, mapped_bus in cfg.get("gocbref_to_bus", {}).items() if mapped_bus == bus]
        sv_ids = [sv_id for sv_id, mapped_bus in cfg.get("svid_to_bus", {}).items() if mapped_bus == bus]
        recent_packets = [
            packet for packet in packets
            if packet.get("bus_num") == bus or packet.get("src_mac") == expected_mac
        ]
        related_alerts = [
            alert for alert in alerts_snapshot
            if _alert_bus(alert) == bus or _alert_src_mac(alert) == expected_mac
        ]
        related_detection_count = sum(int(alert.get("occurrence_count", 1) or 1) for alert in related_alerts)
        last_seen = recent_packets[0].get("received_at") if recent_packets else None
        if related_alerts:
            status = "suspicious"
        elif last_seen:
            status = "active"
        else:
            status = "configured"

        devices.append({
            "bus": bus,
            "expected_mac": expected_mac,
            "expected_ip": cfg.get("mac_to_ip", {}).get(expected_mac),
            "gocb_refs": gocb_refs,
            "sv_ids": sv_ids,
            "last_seen": last_seen,
            "packet_count": len(recent_packets),
            "alert_count": len(related_alerts),
            "detection_count": related_detection_count,
            "status": status,
        })
    return devices


def _build_monitor_devices() -> List[dict[str, Any]]:
    cfg = pipeline.config
    inventory = {device["bus"]: device for device in _build_inventory()}
    status = store.ied_status()
    alerts_snapshot = store.snapshot().get("alerts", [])
    devices: List[dict[str, Any]] = []

    for bus, base in inventory.items():
        live = status.get(bus, {})
        alert_count = sum(1 for alert in alerts_snapshot if _alert_bus(alert) == bus)
        detection_count = sum(
            int(alert.get("occurrence_count", 1) or 1)
            for alert in alerts_snapshot
            if _alert_bus(alert) == bus
        )
        measurements = {
            "voltage": live.get("voltage") or {"phaseA": None, "phaseB": None, "phaseC": None},
            "current": live.get("current") or {"phaseA": None, "phaseB": None, "phaseC": None},
        }
        breaker_status = live.get("breaker_status") or "not observed"
        if alert_count:
            health = "suspicious"
        elif live.get("last_seen"):
            health = "online"
        else:
            health = "not observed"

        sv_expected_mac = None
        sv_publisher_macs = cfg.get("sv_publisher_macs", [])
        if sv_publisher_macs:
            sv_expected_mac = str(sv_publisher_macs[0])

        devices.append({
            **base,
            **live,
            "expected_mac": base.get("expected_mac"),
            "goose_expected_mac": base.get("expected_mac"),
            "sv_expected_mac": sv_expected_mac,
            "goose_source_mac": live.get("goose_src_mac") or live.get("src_mac"),
            "sv_source_mac": live.get("sv_src_mac") or live.get("src_mac"),
            "alert_count": alert_count,
            "detection_count": detection_count,
            "health": health,
            "breaker_status": breaker_status,
            "measurements": measurements,
            "last_capture_offset_seconds": _capture_offset(live.get("last_capture_ts")),
        })
    return devices


def _capture_timeline() -> dict[str, Any]:
    stats = store.snapshot().get("stats", {})
    return {
        "capture_start_ts": stats.get("capture_start_ts"),
        "capture_end_ts": stats.get("capture_end_ts"),
        "capture_duration_seconds": stats.get("capture_duration_seconds"),
        "last_replay": (stats.get("replays") or [None])[0],
    }


def _capture_offset(timestamp: Any) -> Optional[float]:
    stats = store.snapshot().get("stats", {})
    start = stats.get("capture_start_ts")
    if timestamp is None or start is None:
        return None
    try:
        return round(float(timestamp) - float(start), 6)
    except Exception:
        return None


def _alert_bus(alert: dict[str, Any]) -> Optional[str]:
    details = alert.get("details") or {}
    packet = details.get("latest_packet") or details.get("first_packet") or details.get("packet") or {}
    return packet.get("bus_num")


def _alert_src_mac(alert: dict[str, Any]) -> Optional[str]:
    details = alert.get("details") or {}
    packet = details.get("latest_packet") or details.get("first_packet") or details.get("packet") or {}
    return packet.get("src_mac")


def _bus_sort_key(bus: str) -> tuple[int, str]:
    suffix = "".join(char for char in bus if char.isdigit())
    return (int(suffix) if suffix else 9999, bus)


@app.post("/api/clear")
def clear_memory():
    cancel_result = _cancel_active_replay_jobs(wait_for_stop=True)
    pipeline.reset_runtime_state()
    cleared = store.clear()
    cleared["cancelled_replay_jobs"] = cancel_result["cancelled_replay_jobs"]
    return cleared


def _cancel_active_replay_jobs(wait_for_stop: bool = False) -> dict[str, Any]:
    cancellable = {"queued", "running", "cancel_requested"}
    cancelled_job_ids: list[str] = []
    futures_to_wait = []

    for job_id, job in list(replay_jobs.items()):
        if job.get("status") not in cancellable:
            continue
        cancelled_job_ids.append(job_id)

        event = replay_cancel_events.get(job_id)
        if event is not None:
            event.set()

        future = replay_futures.get(job_id)
        if future is not None and future.cancel():
            job.update({
                "status": "cancelled",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "message": "Replay was cancelled before it started.",
            })
        else:
            if future is not None:
                futures_to_wait.append(future)
            job.update({
                "status": "cancel_requested",
                "message": "Replay cancellation requested.",
            })

    if wait_for_stop and futures_to_wait:
        wait(futures_to_wait, timeout=3)

    return {
        "cancelled_replay_jobs": cancelled_job_ids,
        "count": len(cancelled_job_ids),
    }


def _append_alert(payload: Union[DetectionIngestPayload, AlertPayload, dict]) -> dict:
    if isinstance(payload, dict):
        source = payload.get("source", "unknown")
        protocol = payload.get("protocol", "UNKNOWN")
        severity = payload.get("severity", "low")
        message = payload.get("message", "")
        details = payload.get("details") or {}
    else:
        source = payload.source
        protocol = payload.protocol
        severity = payload.severity
        message = payload.message
        details = payload.details or {}

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "protocol": protocol,
        "severity": severity,
        "message": message,
        "details": details,
    }
    saved = store.add_alert(alert)
    store.save()
    return saved


@app.post("/api/alerts")
def create_alert(payload: AlertPayload):
    return _append_alert(payload)


@app.post("/api/ingest-detection")
def ingest_detection(payload: DetectionIngestPayload):
    return _append_alert(payload)


@app.post("/api/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    temp_dir = Path(tempfile.gettempdir()) / "forensic_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    save_path = temp_dir / file.filename
    with save_path.open("wb") as handle:
        handle.write(await file.read())
    return {
        "filename": file.filename,
        "saved_to": str(save_path),
        "message": "PCAP uploaded successfully",
    }


@app.post("/api/replay-pcap")
async def replay_pcap(file: UploadFile = File(...), wait: bool = False):
    temp_dir = Path(tempfile.gettempdir()) / "forensic_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    save_path = temp_dir / file.filename
    with save_path.open("wb") as handle:
        handle.write(await file.read())

    if not wait:
        job_id = uuid.uuid4().hex
        cancel_event = threading.Event()
        replay_jobs[job_id] = {
            "job_id": job_id,
            "filename": file.filename,
            "status": "queued",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "summary": None,
            "progress": {
                "filename": file.filename,
                "packets_processed": 0,
                "total_packets_seen": 0,
                "skipped_packets": 0,
                "goose_packets": 0,
                "sv_packets": 0,
                "analysis_rows": store.state["stats"].get("total_packets", 0),
                "detections_created": 0,
                "elapsed_seconds": 0.0,
            },
            "error": None,
        }
        replay_cancel_events[job_id] = cancel_event
        replay_futures[job_id] = replay_executor.submit(_run_replay_job, job_id, save_path, cancel_event)
        return {
            "job_id": job_id,
            "filename": file.filename,
            "status": "queued",
            "message": "PCAP replay started in the background",
        }

    result = await run_in_threadpool(pipeline.replay_file, str(save_path))
    return {
        "filename": file.filename,
        "alerts": result["alerts"],
        "summary": result["summary"],
        "risk": pipeline.risk_score(),
        "message": "PCAP replayed through rule-based engine",
    }


def _run_replay_job(job_id: str, save_path: Path, cancel_event: threading.Event) -> None:
    job = replay_jobs[job_id]
    try:
        if cancel_event.is_set():
            job.update({
                "status": "cancelled",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "message": "Replay was cancelled before it started.",
            })
            return
        job["status"] = "running"

        def update_progress(progress: dict[str, Any]) -> None:
            job["progress"] = progress

        result = pipeline.replay_file(str(save_path), cancel_event=cancel_event, progress_callback=update_progress)
        status = "cancelled" if result["summary"].get("cancelled") else "complete"
        job.update({
            "status": status,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "summary": result["summary"],
            "progress": result["summary"],
            "risk": pipeline.risk_score(),
            "alerts_created": result["summary"].get("alerts_created"),
            "detections_created": result["summary"].get("detections_created"),
            "packets_processed": result["summary"].get("packets_processed"),
        })
    except Exception as exc:
        job.update({
            "status": "failed",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "error": f"{type(exc).__name__}: {exc}",
        })
    finally:
        replay_cancel_events.pop(job_id, None)
        replay_futures.pop(job_id, None)


@app.get("/api/stream-test")
def stream_test():
    return {"message": "streaming endpoint ready"}
