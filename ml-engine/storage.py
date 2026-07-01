"""
Storage: Simpan raw logs dan alerts ke PostgreSQL
"""

import os
import json
import psycopg2
import psycopg2.extras
from loguru import logger


class DatabaseStorage:
    def __init__(self):
        self.conn = psycopg2.connect(
            host     = os.getenv("POSTGRES_HOST", "postgres"),
            port     = int(os.getenv("POSTGRES_PORT", 5432)),
            dbname   = os.getenv("POSTGRES_DB", "blueteam"),
            user     = os.getenv("POSTGRES_USER", "blueteam"),
            password = os.getenv("POSTGRES_PASSWORD", "blueteam_secret"),
        )
        self.conn.autocommit = True
        logger.info("PostgreSQL connected")

    def save_raw_log(self, entry: dict) -> int:
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO raw_logs (source_ip, agent_host, log_source, raw_message, parsed)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                entry.get("source_ip"),
                entry.get("agent_host", "unknown"),
                entry.get("log_source", "syslog"),
                entry.get("message", "")[:10000],   # batasi 10K char
                json.dumps(entry.get("raw", {})),
            ))
            return cur.fetchone()[0]

    def save_alert(self, alert: dict) -> int:
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts
                    (agent_host, log_source, severity, alert_type, description,
                     raw_log_id, anomaly_score, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                alert.get("agent_host"),
                alert.get("log_source"),
                alert.get("severity"),
                alert.get("alert_type"),
                alert.get("description"),
                alert.get("raw_log_id"),
                alert.get("anomaly_score"),
                json.dumps(alert.get("details", {})),
            ))
            alert_id = cur.fetchone()[0]
            logger.warning(f"[ALERT #{alert_id}] {alert['severity'].upper()} | {alert['alert_type']} | {alert['description']}")
            return alert_id

    def upsert_agent(self, hostname: str, ip: str, os_type: str = "linux"):
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO agents (hostname, ip_address, os_type)
                VALUES (%s, %s, %s)
                ON CONFLICT (hostname) DO UPDATE
                SET last_seen = NOW(), ip_address = EXCLUDED.ip_address, is_active = TRUE
            """, (hostname, ip, os_type))
