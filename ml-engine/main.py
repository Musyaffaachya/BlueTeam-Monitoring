"""
Blueteam Monitor - ML Engine
Entry point: consume logs dari Redis, jalankan deteksi, simpan alert ke PostgreSQL
"""

import time
import json
import os
from loguru import logger

from consumer import LogConsumer
from detector import AnomalyDetector
from storage import DatabaseStorage
from notifier import Notifier


def main():
    logger.info("=" * 60)
    logger.info("  Blueteam ML Engine starting...")
    logger.info("=" * 60)

    # Init semua komponen
    db      = DatabaseStorage()
    detector = AnomalyDetector()
    notifier = Notifier()
    consumer = LogConsumer()

    logger.info("All components initialized. Listening for logs...")

    # Main loop
    for log_entry in consumer.listen():
        try:
            # 1. Simpan raw log ke DB
            log_id = db.save_raw_log(log_entry)

            # 2. Deteksi anomali / serangan
            alerts = detector.analyze(log_entry, log_id)

            # 3. Simpan & kirim notifikasi jika ada alert
            for alert in alerts:
                alert_id = db.save_alert(alert)
                notifier.send(alert, alert_id)

        except Exception as e:
            logger.error(f"Error processing log: {e}")
            continue


if __name__ == "__main__":
    # Tunggu sebentar supaya Redis & Postgres siap
    time.sleep(5)
    main()
