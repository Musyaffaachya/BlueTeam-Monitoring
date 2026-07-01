-- ============================================================
--  Blueteam Monitor - Database Schema
-- ============================================================

-- Raw logs dari semua sumber
CREATE TABLE IF NOT EXISTS raw_logs (
    id          BIGSERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip   INET,
    agent_host  TEXT,
    log_source  TEXT NOT NULL,   -- ssh, syslog, apache, firewall, docker, windows
    raw_message TEXT NOT NULL,
    parsed      JSONB
);

-- Alert hasil deteksi ML
CREATE TABLE IF NOT EXISTS alerts (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_host    TEXT,
    log_source    TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    alert_type    TEXT NOT NULL,   -- brute_force, anomaly, port_scan, dll
    description   TEXT NOT NULL,
    raw_log_id    BIGINT REFERENCES raw_logs(id),
    anomaly_score FLOAT,
    notified      BOOLEAN DEFAULT FALSE,
    details       JSONB
);

-- Status agent yang terdaftar
CREATE TABLE IF NOT EXISTS agents (
    id           BIGSERIAL PRIMARY KEY,
    hostname     TEXT UNIQUE NOT NULL,
    ip_address   INET,
    os_type      TEXT,            -- linux, windows
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active    BOOLEAN DEFAULT TRUE,
    agent_version TEXT
);

-- Statistik per jam untuk Grafana
CREATE TABLE IF NOT EXISTS log_stats_hourly (
    id          BIGSERIAL PRIMARY KEY,
    hour        TIMESTAMPTZ NOT NULL,
    agent_host  TEXT,
    log_source  TEXT,
    log_count   INT DEFAULT 0,
    alert_count INT DEFAULT 0
);
-- Notifikasi history
CREATE TABLE IF NOT EXISTS notifications (
    id         BIGSERIAL PRIMARY KEY,
    sent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_id   BIGINT REFERENCES alerts(id),
    channel    TEXT NOT NULL,   -- telegram, discord
    status     TEXT NOT NULL,   -- sent, failed
    response   TEXT
);

-- ─── Indexes ─────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_raw_logs_received_at  ON raw_logs(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_raw_logs_source_ip    ON raw_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_raw_logs_log_source   ON raw_logs(log_source);
CREATE INDEX IF NOT EXISTS idx_raw_logs_agent_host   ON raw_logs(agent_host);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at     ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity       ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_notified       ON alerts(notified) WHERE notified = FALSE;
CREATE INDEX IF NOT EXISTS idx_alerts_agent_host     ON alerts(agent_host);

-- ─── Views untuk Grafana ──────────────────────────────────────
CREATE OR REPLACE VIEW v_recent_alerts AS
SELECT
    a.id,
    a.created_at,
    a.agent_host,
    a.log_source,
    a.severity,
    a.alert_type,
    a.description,
    a.anomaly_score,
    a.details
FROM alerts a
ORDER BY a.created_at DESC;

CREATE OR REPLACE VIEW v_alert_summary AS
SELECT
    DATE_TRUNC('hour', created_at) AS hour,
    severity,
    log_source,
    COUNT(*) AS total
FROM alerts
GROUP BY 1, 2, 3
ORDER BY 1 DESC;

CREATE OR REPLACE VIEW v_agent_status AS
SELECT
    hostname,
    ip_address,
    os_type,
    last_seen,
    is_active,
    EXTRACT(EPOCH FROM (NOW() - last_seen)) / 60 AS minutes_since_seen
FROM agents
ORDER BY last_seen DESC;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO blueteam;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO blueteam;
