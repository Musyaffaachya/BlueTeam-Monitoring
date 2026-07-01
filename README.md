# Blueteam Monitor

Real-time security log monitoring system with dual-layer threat detection — combining rule-based pattern matching with machine learning (Random Forest + Isolation Forest) trained on the CICIDS 2017 intrusion detection dataset.

Built as a portfolio project to explore Blue Team operations, SIEM architecture, and applied ML for cybersecurity.

---

## What it does

```
Raw logs (SSH, syslog, Apache, Docker, firewall)
        ↓
Fluent Bit agent  →  Fluent Bit receiver  →  ML Engine
        ↓
   Rule-based detection  +  Random Forest  +  Isolation Forest
        ↓
   PostgreSQL  →  Grafana dashboard
        ↓
   Telegram + Discord notifications
```

The system runs as an agent-based architecture: lightweight Fluent Bit agents collect logs from any target machine and forward them to a central server, where a Python ML engine analyzes each entry through two detection layers before storing results and firing real-time alerts.

---

## Why two detection layers

Rule-based detection is fast and precise for known attack signatures (SSH brute force, port scanning, web scanning) but blind to anything not explicitly coded.

Machine learning fills that gap. Two models work together:

| Model | Type | Role |
|---|---|---|
| Random Forest | Supervised | Classifies known attack patterns learned from labeled training data |
| Isolation Forest | Unsupervised | Flags anomalies that deviate from normal traffic, including attacks never seen before |

Both were trained and evaluated on **CICIDS 2017**, a standard academic intrusion detection dataset (1.35M network flow records covering DDoS, port scanning, and brute force attacks).

### Model results

| Metric | Isolation Forest | Random Forest |
|---|---|---|
| Strategy | Semi-supervised (trained on benign traffic only) | Supervised (trained on labeled benign + attack) |
| F1-Score | 46.3% | 99.99% |
| Precision | 33.1% | 100% |
| Recall | 78.3% | 99.98% |
| AUC-ROC | 0.78 | — |

Random Forest achieves near-perfect accuracy on known attack types from the training distribution. Isolation Forest trades accuracy for the ability to catch novel anomalies it was never trained on — it serves as a safety net layered behind the primary classifier.

Full training notebook with EDA, feature correlation analysis, and evaluation: [`ml-engine/blueteam_ml_phase2_v3.ipynb`](ml-engine/blueteam_ml_phase2_v3.ipynb)

---

## Architecture

**Target machine** — runs a Fluent Bit agent that tails `auth.log`, `syslog`, Apache access/error logs, and Docker container logs, forwarding everything to the central server over the Fluent Bit forward protocol.

**Central server** (Docker Compose, 6 services):
- `fluent-bit` — receives forwarded logs, parses by source type
- `ml-engine` — Python service combining rule-based detection (`detector.py`) and ML inference (`ml_predictor.py`)
- `postgres` — stores raw logs, detected alerts, and agent status
- `redis` — message queue (reserved for future caching/scaling)
- `grafana` — real-time dashboard, auto-provisioned
- Notification layer — Telegram bot + Discord webhook, fired on medium severity and above

---

## Detection coverage

| Threat | Detection method | Trigger |
|---|---|---|
| SSH brute force | Rule-based | 5+ failed logins from one IP in 60s |
| Port scanning | Rule-based | 10+ firewall blocks from one IP in 30s |
| Web scanning | Rule-based | 20+ 4xx/error responses from one IP in 60s |
| DDoS / known network attacks | ML (Random Forest) | Classified from 25 network flow features |
| Unknown anomalies | ML (Isolation Forest) | Deviation from learned normal traffic baseline |

---

## Tech stack

**Infrastructure**: Docker Compose, Fluent Bit, PostgreSQL, Redis, Grafana
**ML Engine**: Python, scikit-learn, pandas, numpy, joblib
**Dataset**: CICIDS 2017 (Canadian Institute for Cybersecurity)
**Notifications**: Telegram Bot API, Discord Webhooks

---

## Project structure

```
blueteam-monitor/
├── central/                       Central server (run here)
│   ├── docker-compose.yml
│   ├── .env.example
│   ├── setup.sh
│   ├── fluent-bit/
│   │   ├── fluent-bit.conf        Receiver config
│   │   └── parsers.conf
│   ├── postgres/
│   │   └── init.sql               Schema: raw_logs, alerts, agents
│   └── grafana/
│       ├── provisioning/
│       └── dashboards/blueteam-main.json
├── ml-engine/
│   ├── main.py
│   ├── consumer.py                HTTP ingest server
│   ├── detector.py                Rule-based + ML orchestration
│   ├── ml_predictor.py            Random Forest + Isolation Forest inference
│   ├── storage.py                 PostgreSQL writes
│   ├── notifier.py                Telegram + Discord
│   ├── models/                    Trained model artifacts (.joblib)
│   ├── datasets/cicids/           CICIDS 2017 CSVs (not committed, see below)
│   └── blueteam_ml_phase2_v3.ipynb   Training notebook
└── agent/                         Deploy to target machines
    ├── fluent-bit/agent-self.conf
    └── deploy-agent-linux.sh
```

---

## Quick start

### 1. Central server

```bash
cd central
cp .env.example .env
# optionally fill in TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL
chmod +x setup.sh
./setup.sh
```

This brings up all 5 Docker services. Dashboard available at `http://localhost:3000` (`admin` / `blueteam_grafana`).

### 2. Train the ML models (optional — pre-trained models included)

Download [CICIDS 2017](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset) into `ml-engine/datasets/cicids/`, then run the notebook:

```bash
cd ml-engine
jupyter notebook blueteam_ml_phase2_v3.ipynb
```

This regenerates `models/random_forest.joblib`, `models/isolation_forest.joblib`, and associated scalers.

### 3. Deploy an agent

```bash
cd agent
chmod +x deploy-agent-linux.sh
sudo ./deploy-agent-linux.sh <CENTRAL_SERVER_IP>
```

---

## Notes on the dataset

CICIDS 2017 CSVs are not committed to this repository (too large for git). The notebook includes the full data loading, cleaning, and feature engineering pipeline, with results and visualizations saved as PNGs for reference even without re-running the dataset download.

---

## Roadmap

- [x] Phase 1 — Infrastructure (Docker Compose, pipeline, rule-based detection)
- [x] Phase 2 — ML training on CICIDS 2017 (Isolation Forest + Random Forest)
- [x] Phase 3 — ML integration into real-time detection pipeline
- [x] Phase 4 — Agent deployment, self-monitoring validation
- [x] Phase 5 — Telegram + Discord notifications
- [ ] Phase 6 — Windows Event Log agent support
- [ ] Phase 7 — Threat intelligence integration (AbuseIPDB)
- [ ] Phase 8 — TLS encryption for agent-to-server communication

---

## Author

Built by Musa — Cyber Security Engineering student, Politeknik Negeri Cilacap.

This project was developed as a hands-on exploration of SIEM architecture, log pipeline design, and applied machine learning for intrusion detection, separate from the author's RF-based drone detection thesis work.
