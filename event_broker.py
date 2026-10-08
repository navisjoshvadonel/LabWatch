"""
event_broker.py
College Lab PC Fault Reporting System (LabPulse)
High-Performance Server-Sent Events (SSE) Live Event Stream Broker

Provides real-time pub/sub push notifications for:
- Live PC status transitions (Online <-> Offline <-> Degraded)
- Real-time ticket creation, triage, and resolution
- Instant automated remediation playbook execution logs
- Pre-lab exam readiness audit sweeps
- Real-time audible audio chime & toast alerts on technician dashboards
"""

import json
import logging
import queue
import threading
import time
from typing import Generator, Any

logger = logging.getLogger("LabPulse.EventBroker")


class LabPulseEventBroker:
    """
    Thread-safe, in-memory Publish/Subscribe message broker for Server-Sent Events (SSE).
    Enables zero-latency push to connected client dashboards with automatic heartbeat pinging.
    """
    def __init__(self, heartbeat_interval: float = 15.0):
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()
        self.heartbeat_interval = heartbeat_interval
        self._total_events_published = 0

    def subscribe(self) -> queue.Queue:
        """Register a new SSE client subscriber queue."""
        q = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
            count = len(self._subscribers)
        logger.debug(f"[+] Client subscribed to SSE stream (active listeners: {count})")
        return q

    def unsubscribe(self, q: queue.Queue):
        """Remove a disconnected SSE subscriber queue."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)
                count = len(self._subscribers)
            else:
                count = len(self._subscribers)
        logger.debug(f"[-] Client unsubscribed from SSE stream (remaining listeners: {count})")

    def publish(self, event_type: str, data: dict[str, Any]):
        """
        Broadcast an event to all connected clients.
        If a subscriber's queue is full, discard the oldest event to prevent memory leaks.
        """
        self._total_events_published += 1
        payload = {
            "event": event_type,
            "data": data,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        json_str = json.dumps(payload)
        sse_chunk = f"event: {event_type}\ndata: {json_str}\n\n"

        with self._lock:
            subscribers = list(self._subscribers)

        for q in subscribers:
            try:
                q.put_nowait(sse_chunk)
            except queue.Full:
                try:
                    # Drop oldest message to prevent stalled consumers from choking the broker
                    q.get_nowait()
                    q.put_nowait(sse_chunk)
                except Exception:
                    pass

        logger.info(f"[SSE Broadcast] '{event_type}' sent to {len(subscribers)} clients.")

    def stream(self, q: queue.Queue) -> Generator[str, None, None]:
        """
        Generator function yielding SSE formatted messages and periodic heartbeats.
        Yields comment ping packets to keep TCP connections alive.
        """
        # Send initial connection handshake event
        initial_event = {
            "event": "connected",
            "data": {"status": "connected", "broker": "LabPulse-SSE-v2", "server_time": time.strftime("%Y-%m-%d %H:%M:%S")},
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        yield f"event: connected\ndata: {json.dumps(initial_event)}\n\n"

        last_heartbeat = time.time()
        try:
            while True:
                now = time.time()
                timeout = max(0.5, self.heartbeat_interval - (now - last_heartbeat))
                try:
                    msg = q.get(timeout=timeout)
                    yield msg
                except queue.Empty:
                    # Send keep-alive SSE comment
                    yield f": ping {int(time.time())}\n\n"
                    last_heartbeat = time.time()
        except GeneratorExit:
            self.unsubscribe(q)
        except Exception as e:
            logger.warning(f"[-] SSE Stream disconnected: {e}")
            self.unsubscribe(q)


# Singleton event broker instance
event_broker = LabPulseEventBroker(heartbeat_interval=15.0)
