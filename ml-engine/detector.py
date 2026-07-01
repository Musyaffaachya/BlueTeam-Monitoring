"""
Detector: Deteksi ancaman menggunakan dua lapis:
  Layer 1 (cepat)  → Rule-based untuk pola yang jelas
  Layer 2 (cerdas) → ML (Random Forest + Isolation Forest)
"""

import re
import time
from collections import defaultdict, deque
from loguru import logger
from typing import List

from ml_predictor import MLPredictor


# ─── Rule Patterns ───────────────────────────────────────────────
SSH_FAIL_PATTERN     = re.compile(r"Failed password|Invalid user|authentication failure", re.I)
SSH_ACCEPTED_PATTERN = re.compile(r"Accepted (password|publickey) for (\S+) from ([\d.]+)", re.I)
UFW_BLOCK_PATTERN    = re.compile(r"\[UFW BLOCK\].*SRC=([\d.]+).*DPT=(\d+)", re.I)
APACHE_STATUS_RE     = re.compile(r'" (\d{3}) ')


class AnomalyDetector:
    def __init__(self):
        # ── Rate tracking per IP ──────────────────────────────
        self._ssh_failures : dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._fw_blocks    : dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._web_scans    : dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # ── Thresholds ────────────────────────────────────────
        self.SSH_BRUTE_THRESHOLD   = 5
        self.SSH_BRUTE_WINDOW      = 60
        self.FW_PORTSCAN_THRESHOLD = 10
        self.FW_PORTSCAN_WINDOW    = 30
        self.WEB_SCAN_THRESHOLD    = 20
        self.WEB_SCAN_WINDOW       = 60

        # ── ML Engine ─────────────────────────────────────────
        self.ml = MLPredictor()

        logger.info("AnomalyDetector initialized")
        logger.info(f"  Rule-based : ✅ aktif")
        logger.info(f"  ML engine  : {'✅ aktif' if self.ml.ready else '⚠️  tidak tersedia'}")

    def analyze(self, log_entry: dict, log_id: int) -> List[dict]:
        alerts = []
        source = log_entry.get('log_source', '')
        msg    = log_entry.get('message', '')
        host   = log_entry.get('agent_host', 'unknown')
        now    = time.time()

        # ── Layer 1: Rule-based (selalu jalan) ───────────────
        if source == 'ssh':
            alerts += self._check_ssh(msg, host, log_id, now)
        elif source == 'firewall':
            alerts += self._check_firewall(msg, host, log_id, now)
        elif source == 'apache':
            alerts += self._check_apache(msg, host, log_id, now, log_entry)

        # ── Layer 2: ML Detection ─────────────────────────────
        ml_alert = self._check_ml(log_entry, log_id, host)
        if ml_alert:
            # Hindari duplikat: skip ML alert kalau rule-based sudah detect
            if not alerts:
                alerts.append(ml_alert)
            else:
                # Tambahkan ML score ke alert yang sudah ada sebagai info tambahan
                for a in alerts:
                    if 'details' not in a:
                        a['details'] = {}
                    a['details']['ml_confirmed'] = True
                    a['details']['rf_attack_prob'] = ml_alert.get('details', {}).get('rf_attack_prob')

        return alerts

    # ─── Rule-based Checks ───────────────────────────────────────

    def _check_ssh(self, msg: str, host: str, log_id: int, now: float) -> List[dict]:
        alerts = []
        if SSH_FAIL_PATTERN.search(msg):
            ip = self._extract_ip(msg)
            if ip:
                q = self._ssh_failures[ip]
                q.append(now)
                recent = [t for t in q if now - t <= self.SSH_BRUTE_WINDOW]
                if len(recent) >= self.SSH_BRUTE_THRESHOLD:
                    alerts.append(self._make_alert(
                        agent_host  = host,
                        log_source  = 'ssh',
                        severity    = 'high',
                        alert_type  = 'ssh_brute_force',
                        description = f"Brute force SSH dari {ip}: {len(recent)} gagal dalam {self.SSH_BRUTE_WINDOW}s",
                        raw_log_id  = log_id,
                        details     = {'source_ip': ip, 'failure_count': len(recent), 'method': 'rule_based'},
                    ))
        return alerts

    def _check_firewall(self, msg: str, host: str, log_id: int, now: float) -> List[dict]:
        alerts = []
        m = UFW_BLOCK_PATTERN.search(msg)
        if m:
            src_ip, dst_port = m.group(1), m.group(2)
            q = self._fw_blocks[src_ip]
            q.append(now)
            recent = [t for t in q if now - t <= self.FW_PORTSCAN_WINDOW]
            if len(recent) >= self.FW_PORTSCAN_THRESHOLD:
                alerts.append(self._make_alert(
                    agent_host  = host,
                    log_source  = 'firewall',
                    severity    = 'medium',
                    alert_type  = 'port_scan',
                    description = f"Port scan dari {src_ip}: {len(recent)} block dalam {self.FW_PORTSCAN_WINDOW}s",
                    raw_log_id  = log_id,
                    details     = {'source_ip': src_ip, 'block_count': len(recent), 'last_port': dst_port, 'method': 'rule_based'},
                ))
        return alerts

    def _check_apache(self, msg: str, host: str, log_id: int, now: float, entry: dict) -> List[dict]:
        alerts = []
        raw       = entry.get('raw', {})
        status    = str(raw.get('status', ''))
        client_ip = raw.get('client_ip') or self._extract_ip(msg)

        if status in ('404', '403', '400') and client_ip:
            q = self._web_scans[client_ip]
            q.append(now)
            recent = [t for t in q if now - t <= self.WEB_SCAN_WINDOW]
            if len(recent) >= self.WEB_SCAN_THRESHOLD:
                alerts.append(self._make_alert(
                    agent_host  = host,
                    log_source  = 'apache',
                    severity    = 'medium',
                    alert_type  = 'web_scan',
                    description = f"Web scanning dari {client_ip}: {len(recent)} error dalam {self.WEB_SCAN_WINDOW}s",
                    raw_log_id  = log_id,
                    details     = {'source_ip': client_ip, 'request_count': len(recent), 'last_status': status, 'method': 'rule_based'},
                ))
        return alerts

    # ─── ML Check ────────────────────────────────────────────────

    def _check_ml(self, log_entry: dict, log_id: int, host: str) -> dict | None:
        result = self.ml.predict(log_entry)
        if result is None or not result.get('is_attack'):
            return None

        method     = result.get('method', 'ml')
        severity   = result.get('severity', 'medium')
        atk_prob   = result.get('rf_attack_prob', 0.0)
        if_score   = result.get('if_score', 0.0)

        if method == 'random_forest':
            description = (f"ML (Random Forest) mendeteksi serangan jaringan "
                           f"dengan probabilitas {atk_prob*100:.1f}%")
        else:
            description = (f"ML (Isolation Forest) mendeteksi anomali "
                           f"(score={if_score:.4f}, threshold={result.get('if_threshold', 0):.4f})")

        return self._make_alert(
            agent_host  = host,
            log_source  = log_entry.get('log_source', 'unknown'),
            severity    = severity,
            alert_type  = result.get('attack_type', 'ml_detected'),
            description = description,
            raw_log_id  = log_id,
            anomaly_score = if_score,
            details     = {
                'method'        : method,
                'rf_prediction' : result.get('rf_prediction'),
                'rf_attack_prob': atk_prob,
                'rf_confidence' : result.get('rf_confidence'),
                'if_score'      : if_score,
                'if_prediction' : result.get('if_prediction'),
            },
        )

    # ─── Helpers ─────────────────────────────────────────────────

    def _extract_ip(self, msg: str) -> str | None:
        m = re.search(r'from ([\d.]+)', msg)
        return m.group(1) if m else None

    def _make_alert(self, **kwargs) -> dict:
        return kwargs
