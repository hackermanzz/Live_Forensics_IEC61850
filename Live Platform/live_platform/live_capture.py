from __future__ import annotations

from datetime import datetime, timezone
import queue
import threading
from time import monotonic, perf_counter
from typing import Any, Callable, Dict

GOOSE_SV_BPF_FILTER = "ether proto 0x88b8 or ether proto 0x88ba or (vlan and (ether proto 0x88b8 or ether proto 0x88ba))"
PacketQueueItem = tuple[Any, int, Any, str, float]
PacketBatch = list[tuple[Any, int, Any, str]]


class LiveCaptureController:
    """Controls live packet capture and feeds packets into the detection pipeline."""

    def __init__(self) -> None:
        self.enabled = False
        self.interface: str | None = None
        self.started_at: str | None = None
        self._started_monotonic: float | None = None
        self.packet_count = 0
        self.processed_packet_count = 0
        self.ignored_packet_count = 0
        self.dropped_packet_count = 0
        self.processing_batch_count = 0
        self.processing_total_batch_size = 0
        self.processing_largest_batch_size = 0
        self.processing_total_seconds = 0.0
        self.processing_max_seconds = 0.0
        self.queue_wait_total_seconds = 0.0
        self.queue_wait_max_seconds = 0.0
        self.last_error: str | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._processing_thread: threading.Thread | None = None
        self._packet_queue: queue.Queue[PacketQueueItem] | None = None
        self.processing_batch_size = 100
        self.processing_max_batch_limit = 500
        self.processing_batch_wait_seconds = 0.02
        self.queue_limit = 20000
        self.message = "Live capture is ready to configure. No interface is running."

    def interfaces(self) -> Dict[str, Any]:
        try:
            from scapy.all import get_working_ifaces

            interfaces = []
            for iface in get_working_ifaces():
                name = getattr(iface, "name", None) or str(iface)
                description = getattr(iface, "description", None) or name
                mac = getattr(iface, "mac", None)
                ip = getattr(iface, "ip", None)
                interfaces.append({
                    "name": name,
                    "description": description,
                    "mac": mac,
                    "ip": ip,
                    "label": self._interface_label(name, description, ip),
                })
            return {
                "interfaces": interfaces,
                "error": None,
                "message": "Select the interface connected to the mirrored/TAP network.",
            }
        except Exception as exc:
            return {
                "interfaces": [],
                "error": str(exc),
                "message": "Interface discovery unavailable. Enter an interface name manually.",
            }

    def start(
        self,
        interface: str | None = None,
        packet_handler: Callable[[Any, int, Any, str], Any] | None = None,
        packet_batch_handler: Callable[[PacketBatch], Any] | None = None,
    ) -> Dict[str, Any]:
        if self.enabled:
            return self.status()
        self.enabled = True
        self.interface = interface or "not_configured"
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._started_monotonic = monotonic()
        self.packet_count = 0
        self.processed_packet_count = 0
        self.ignored_packet_count = 0
        self.dropped_packet_count = 0
        self.processing_batch_count = 0
        self.processing_total_batch_size = 0
        self.processing_largest_batch_size = 0
        self.processing_total_seconds = 0.0
        self.processing_max_seconds = 0.0
        self.queue_wait_total_seconds = 0.0
        self.queue_wait_max_seconds = 0.0
        self.last_error = None
        self._stop_event.clear()
        self._packet_queue = queue.Queue(maxsize=self.queue_limit)

        if interface and packet_handler:
            self.message = f"Live capture running on {interface}."
            self._processing_thread = threading.Thread(
                target=self._process_loop,
                args=(packet_handler, packet_batch_handler),
                daemon=True,
            )
            self._thread = threading.Thread(
                target=self._sniff_loop,
                args=(interface,),
                daemon=True,
            )
            self._processing_thread.start()
            self._thread.start()
        else:
            self.message = "Live capture armed, but no interface was provided. Select an interface on the campus machine to sniff packets."
        return self.status()

    def stop(self) -> Dict[str, Any]:
        self.enabled = False
        self._stop_event.set()
        self.message = "Live capture stopped."
        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=2)
        return self.status()

    def diagnostic(self, interface: str | None = None, duration_seconds: float = 5.0) -> Dict[str, Any]:
        if not interface:
            return {
                "status": "not_started",
                "interface": None,
                "duration_seconds": duration_seconds,
                "packets_seen": 0,
                "error": "interface_required",
                "message": "Select an interface before running diagnostic capture.",
            }
        if self.enabled:
            return {
                "status": "busy",
                "interface": self.interface,
                "duration_seconds": duration_seconds,
                "packets_seen": 0,
                "error": "live_capture_running",
                "message": "Stop live capture before running a diagnostic capture.",
            }

        started_at = datetime.now(timezone.utc).isoformat()
        packets_seen = 0
        duration_seconds = max(1.0, min(float(duration_seconds or 5.0), 30.0))

        try:
            from scapy.all import sniff

            def count_packet(_: Any) -> None:
                nonlocal packets_seen
                packets_seen += 1

            sniff(iface=interface, prn=count_packet, store=False, timeout=duration_seconds)
            return {
                "status": "complete",
                "interface": interface,
                "duration_seconds": duration_seconds,
                "packets_seen": packets_seen,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
                "message": f"Diagnostic capture saw {packets_seen} packets. Detection was not run.",
            }
        except Exception as exc:
            return {
                "status": "failed",
                "interface": interface,
                "duration_seconds": duration_seconds,
                "packets_seen": packets_seen,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
                "message": f"Diagnostic capture failed: {exc}",
            }

    def status(self) -> Dict[str, Any]:
        elapsed_seconds = self._elapsed_seconds()
        return {
            "enabled": self.enabled,
            "interface": self.interface,
            "started_at": self.started_at,
            "mode": "sniffing" if self.enabled and self.interface != "not_configured" else "control_plane_ready",
            "capture_filter": GOOSE_SV_BPF_FILTER,
            "packet_count": self.packet_count,
            "processed_packet_count": self.processed_packet_count,
            "ignored_packet_count": self.ignored_packet_count,
            "dropped_packet_count": self.dropped_packet_count,
            "queue_depth": self._packet_queue.qsize() if self._packet_queue is not None else 0,
            "queue_limit": self.queue_limit,
            "captured_packets_per_second": round(self.packet_count / elapsed_seconds, 2) if elapsed_seconds > 0 else 0.0,
            "processed_packets_per_second": round(self.processed_packet_count / elapsed_seconds, 2) if elapsed_seconds > 0 else 0.0,
            "processing_batch_count": self.processing_batch_count,
            "processing_avg_batch_size": round(self.processing_total_batch_size / max(self.processing_batch_count, 1), 2),
            "processing_max_batch_size": self.processing_largest_batch_size,
            "processing_batch_limit": self.processing_max_batch_limit,
            "processing_avg_ms": round((self.processing_total_seconds / max(self.processing_batch_count, 1)) * 1000, 3),
            "processing_max_ms": round(self.processing_max_seconds * 1000, 3),
            "queue_wait_avg_ms": round((self.queue_wait_total_seconds / max(self.processed_packet_count, 1)) * 1000, 3),
            "queue_wait_max_ms": round(self.queue_wait_max_seconds * 1000, 3),
            "batch_wait_ms": round(self.processing_batch_wait_seconds * 1000, 3),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "last_error": self.last_error,
            "message": self.message,
        }

    def _sniff_loop(self, interface: str) -> None:
        try:
            from scapy.all import Ether, sniff

            def handle_packet(pkt: Any) -> None:
                if self._stop_event.is_set():
                    return
                if not self._is_goose_or_sv(pkt, Ether):
                    self.ignored_packet_count += 1
                    return
                self.packet_count += 1
                ts = getattr(pkt, "time", None)
                try:
                    if self._packet_queue is not None:
                        self._packet_queue.put_nowait((pkt, self.packet_count, ts, f"live:{interface}", monotonic()))
                except queue.Full:
                    self.dropped_packet_count += 1

            try:
                sniff(
                    iface=interface,
                    filter=GOOSE_SV_BPF_FILTER,
                    prn=handle_packet,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            except Exception as exc:
                self.last_error = f"BPF filter unavailable, using software filter: {exc}"
                sniff(iface=interface, prn=handle_packet, store=False, stop_filter=lambda _: self._stop_event.is_set())
        except Exception as exc:
            self.last_error = str(exc)
            self.message = f"Live capture error: {exc}"
        finally:
            self.enabled = False

    def _process_loop(
        self,
        packet_handler: Callable[[Any, int, Any, str], Any],
        packet_batch_handler: Callable[[PacketBatch], Any] | None = None,
    ) -> None:
        while not self._stop_event.is_set() or (self._packet_queue is not None and not self._packet_queue.empty()):
            try:
                if self._packet_queue is None:
                    return
                first_item = self._packet_queue.get(timeout=0.25)
            except queue.Empty:
                continue

            batch = [first_item]
            if packet_batch_handler is not None and self._packet_queue is not None:
                target_batch_size = self._target_batch_size()
                deadline = monotonic() + self.processing_batch_wait_seconds
                while len(batch) < target_batch_size:
                    try:
                        timeout = max(0.0, deadline - monotonic())
                        if timeout <= 0.0:
                            break
                        batch.append(self._packet_queue.get(timeout=timeout))
                    except queue.Empty:
                        break

            process_started = perf_counter()
            try:
                handler_batch = [(pkt, index, ts, source) for pkt, index, ts, source, _ in batch]
                if packet_batch_handler is not None:
                    packet_batch_handler(handler_batch)
                    self.processed_packet_count += len(batch)
                else:
                    for pkt, index, ts, source in handler_batch:
                        packet_handler(pkt, index, ts, source)
                        self.processed_packet_count += 1
                self._record_processing_stats(batch, perf_counter() - process_started)
            except Exception as exc:
                self.last_error = f"Packet processing error: {exc}"
            finally:
                if self._packet_queue is not None:
                    for _ in batch:
                        self._packet_queue.task_done()

    def _target_batch_size(self) -> int:
        if self._packet_queue is None:
            return self.processing_batch_size
        queued = self._packet_queue.qsize()
        if queued >= self.processing_batch_size * 4:
            return self.processing_max_batch_limit
        if queued >= self.processing_batch_size:
            return min(self.processing_max_batch_limit, self.processing_batch_size * 2)
        return self.processing_batch_size

    def _record_processing_stats(self, batch: list[PacketQueueItem], elapsed_seconds: float) -> None:
        now = monotonic()
        self.processing_batch_count += 1
        self.processing_total_batch_size += len(batch)
        self.processing_largest_batch_size = max(self.processing_largest_batch_size, len(batch))
        self.processing_total_seconds += elapsed_seconds
        self.processing_max_seconds = max(self.processing_max_seconds, elapsed_seconds)
        for _, _, _, _, enqueued_at in batch:
            queue_wait = max(0.0, now - enqueued_at)
            self.queue_wait_total_seconds += queue_wait
            self.queue_wait_max_seconds = max(self.queue_wait_max_seconds, queue_wait)

    def _elapsed_seconds(self) -> float:
        if self._started_monotonic is None:
            return 0.0
        return max(0.0, monotonic() - self._started_monotonic)

    def _is_goose_or_sv(self, pkt: Any, ether_layer: Any) -> bool:
        try:
            if ether_layer not in pkt:
                return False

            eth_type = pkt[ether_layer].type
            if eth_type in {0x88B8, 0x88BA}:
                return True

            if eth_type == 0x8100:
                try:
                    from scapy.all import Dot1Q

                    return Dot1Q in pkt and pkt[Dot1Q].type in {0x88B8, 0x88BA}
                except Exception:
                    return False
            return False
        except Exception:
            return False

    def _interface_label(self, name: str, description: str, ip: str | None) -> str:
        if ip:
            return f"{description} ({name}, {ip})"
        if description != name:
            return f"{description} ({name})"
        return name
