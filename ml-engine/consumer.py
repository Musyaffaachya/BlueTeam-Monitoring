"""
Consumer: Terima log dari Fluent Bit via HTTP POST
Perbaikan: handle field 'log' dan deteksi source dari isi pesan
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from queue import Queue
from loguru import logger
from typing import Generator
import re


_log_queue: Queue = Queue(maxsize=10000)


class _IngestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ingest":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")

        count = 0
        for line in body.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                _log_queue.put_nowait(data)
                count += 1
            except Exception:
                pass

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass  # suppress HTTP access log


class LogConsumer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.server = HTTPServer((host, port), _IngestHandler)
        t = threading.Thread(target=self.server.serve_forever, daemon=True)
        t.start()
        logger.info(f"HTTP ingest server listening on {host}:{port}/ingest")

    def listen(self) -> Generator[dict, None, None]:
        logger.info("Waiting for logs from Fluent Bit...")
        while True:
            try:
                raw = _log_queue.get(timeout=5)
                entry = self._normalize(raw)
                if entry:
                    yield entry
            except Exception:
                continue

    def _normalize(self, data: dict) -> dict | None:
        try:
            # Fluent Bit HTTP output bisa kirim field 'log' atau 'message'
            msg = (data.get("message") or
                   data.get("log") or
                   data.get("msg") or
                   "")

            # Pastikan msg adalah string
            if not isinstance(msg, str):
                msg = str(msg)

            # Deteksi source dari tag ATAU isi pesan
            source = self._detect_source(data, msg)

            return {
                "agent_host": data.get("agent_host", "unknown"),
                "log_source": source,
                "source_ip":  data.get("client_ip") or data.get("source_ip"),
                "message":    msg,
                "raw":        data,
            }
        except Exception as e:
            logger.debug(f"Normalize error: {e}")
            return None

    def _detect_source(self, data: dict, msg: str) -> str:
        # Cek dari tag dulu
        tag = str(data.get("tag", "")).lower()
        if tag:
            if "ssh" in tag or "auth" in tag:     return "ssh"
            if "apache" in tag or "nginx" in tag:  return "apache"
            if "docker" in tag:                    return "docker"
            if "firewall" in tag or "ufw" in tag:  return "firewall"
            if "windows" in tag:                   return "windows"

        # Kalau tidak ada tag, deteksi dari isi pesan
        msg_lower = msg.lower()

        # SSH / Auth patterns
        if any(p in msg_lower for p in [
            "sshd", "failed password", "accepted password",
            "invalid user", "pam_unix", "authentication failure",
            "sudo:", "su:", "gdm-password", "login keyring",
        ]):
            return "ssh"

        # Apache / Web patterns
        if any(p in msg_lower for p in [
            "apache", "nginx", "http/1.", "http/2",
            "get /", "post /", "put /", "head /",
            "mod_", "php-fpm",
        ]):
            return "apache"

        # UFW / Firewall patterns
        if any(p in msg_lower for p in [
            "ufw block", "ufw allow", "[ufw",
            "iptables", "netfilter",
        ]):
            return "firewall"

        # Docker patterns
        if any(p in msg_lower for p in [
            "docker", "containerd", "container",
        ]):
            return "docker"

        # Default
        return "syslog"
