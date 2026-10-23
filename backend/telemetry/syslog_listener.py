import os
import socket
import threading
import json
import re
from typing import Optional, Callable
from datetime import datetime, timezone

class SyslogListener:
    """
    Workstream D: Optional, lightweight UDP Syslog-style listener for Suraksha AI.
    - Bound to loopback (127.0.0.1) by default.
    - Disabled by default (SURAKSHA_SYSLOG_ENABLED=0 or false).
    - Normalized into telemetry events and routed through the common pipeline.
    - Handles malformed packets and listener shutdown safely.
    """
    def __init__(
        self,
        pipeline_callback: Optional[Callable[[dict, str, str], Any]] = None,
        host: str = "127.0.0.1",
        port: int = 5514
    ):
        self.host = host
        self.port = int(os.environ.get("SURAKSHA_SYSLOG_PORT", port))
        self.pipeline_callback = pipeline_callback
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.is_enabled = os.environ.get("SURAKSHA_SYSLOG_ENABLED", "0").lower() in ("1", "true", "yes")

    def parse_syslog_message(self, raw_bytes: bytes) -> dict:
        """
        Parses raw UDP syslog packet (RFC 3164/5424 text or JSON payload).
        Extracts source IP, user, event type, and details safely.
        """
        try:
            text = raw_bytes.decode("utf-8", errors="replace").strip()
        except Exception:
            text = str(raw_bytes)

        # Check if direct JSON string
        if text.startswith("{") and text.endswith("}"):
            try:
                data = json.loads(text)
                return {
                    "source_ip": data.get("source_ip") or data.get("src_ip") or "127.0.0.1",
                    "user_id": data.get("user_id") or data.get("user") or "syslog_user",
                    "event_type": data.get("event_type") or data.get("action") or "SYSLOG_MSG",
                    "asset_id": data.get("asset_id") or data.get("host") or "syslog-host",
                    "asset_criticality": data.get("asset_criticality", "MEDIUM"),
                    "payload_metric": float(data.get("payload_metric", 1.0)),
                    "details": data.get("details") or text
                }
            except Exception:
                pass

        # Regex parsing for RFC 3164 style: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        pri_match = re.match(r"^<(\d+)>(.*)$", text)
        msg_body = pri_match.group(2) if pri_match else text

        # Simple extraction heuristics
        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", msg_body)
        src_ip = ip_match.group(0) if ip_match else "127.0.0.1"

        user_match = re.search(r"\buser[=:\s]+([a-zA-Z0-9_\-\.]+)", msg_body, re.IGNORECASE)
        user_id = user_match.group(1) if user_match else "syslog_source"

        event_type = "SYSLOG_EVENT"
        lower_body = msg_body.lower()
        if "failed" in lower_body or "failure" in lower_body:
            event_type = "LOGIN_FAILED"
        elif "sudo" in lower_body or "privilege" in lower_body:
            event_type = "SUDO_EXEC"
        elif "beacon" in lower_body or "c2" in lower_body:
            event_type = "C2_BEACON"
        elif "transfer" in lower_body or "bytes" in lower_body:
            event_type = "BYTES_OUT"

        return {
            "source_ip": src_ip,
            "user_id": user_id,
            "event_type": event_type,
            "asset_id": "syslog-gateway",
            "asset_criticality": "MEDIUM",
            "payload_metric": 1.0,
            "details": f"Syslog packet: {msg_body[:200]}"
        }

    def start(self):
        if not self.is_enabled:
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(1.0)
            self.sock.bind((self.host, self.port))
            self.running = True
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
        except Exception:
            self.running = False

    def _listen_loop(self):
        while self.running and self.sock:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue
                parsed = self.parse_syslog_message(data)
                if self.pipeline_callback:
                    self.pipeline_callback(parsed, f"SYSLOG_{addr[0]}", "SYSTEM")
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
