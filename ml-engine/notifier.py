"""
Notifier: Kirim alert ke Telegram dan Discord
Fix: escape karakter khusus Markdown supaya tidak error
"""

import os
import re
import httpx
from loguru import logger


SEVERITY_EMOJI = {
    "low":      "🔵",
    "medium":   "🟡",
    "high":     "🔴",
    "critical": "🚨",
}


class Notifier:
    def __init__(self):
        self.telegram_token   = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.discord_webhook  = os.getenv("DISCORD_WEBHOOK_URL", "")

        if self.telegram_token:
            logger.info("Telegram notifier: enabled")
        if self.discord_webhook:
            logger.info("Discord notifier: enabled")
        if not self.telegram_token and not self.discord_webhook:
            logger.warning("No notifier configured (Telegram / Discord)")

    def send(self, alert: dict, alert_id: int):
        severity = alert.get("severity", "low")
        if severity == "low":
            return

        if self.telegram_token:
            self._send_telegram(alert, alert_id)
        if self.discord_webhook:
            self._send_discord(alert, alert_id)

    @staticmethod
    def _escape_md(text) -> str:
        """Escape karakter spesial Telegram Markdown (legacy mode)."""
        if text is None:
            return "-"
        text = str(text)
        # Karakter yang perlu di-escape di Telegram Markdown (legacy)
        for ch in ['_', '*', '[', ']', '`']:
            text = text.replace(ch, f'\\{ch}')
        return text

    def _format_message(self, alert: dict, alert_id: int) -> str:
        emoji   = SEVERITY_EMOJI.get(alert.get("severity", "low"), "⚪")
        details = alert.get("details", {}) or {}

        detail_lines = []
        for k, v in details.items():
            k_safe = self._escape_md(k)
            v_safe = self._escape_md(v)
            detail_lines.append(f"  • {k_safe}: {v_safe}")
        detail_str = "\n".join(detail_lines)

        host        = self._escape_md(alert.get('agent_host', 'unknown'))
        log_source  = self._escape_md(alert.get('log_source', '-'))
        alert_type  = self._escape_md(alert.get('alert_type', '-'))
        severity    = self._escape_md(alert.get('severity', '-').upper())
        description = self._escape_md(alert.get('description', '-'))

        return (
            f"{emoji} *BLUETEAM ALERT #{alert_id}*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🖥 Host: `{host}`\n"
            f"📋 Source: `{log_source}`\n"
            f"⚡ Type: `{alert_type}`\n"
            f"🎯 Severity: *{severity}*\n"
            f"📝 {description}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"{detail_str}"
        )

    def _send_telegram(self, alert: dict, alert_id: int):
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        message = self._format_message(alert, alert_id)
        try:
            r = httpx.post(url, json={
                "chat_id":    self.telegram_chat_id,
                "text":       message,
                "parse_mode": "Markdown",
            }, timeout=10)
            if not r.is_success:
                logger.error(f"Telegram error: {r.text}")
                # Fallback: kirim tanpa markdown sama sekali
                self._send_telegram_plain(alert, alert_id)
            else:
                logger.info(f"Telegram sent: alert #{alert_id}")
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")

    def _send_telegram_plain(self, alert: dict, alert_id: int):
        """Fallback tanpa markdown formatting sama sekali."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        emoji   = SEVERITY_EMOJI.get(alert.get("severity", "low"), "⚪")
        details = alert.get("details", {}) or {}
        detail_str = "\n".join(f"  - {k}: {v}" for k, v in details.items())

        plain_msg = (
            f"{emoji} BLUETEAM ALERT #{alert_id}\n"
            f"--------------------\n"
            f"Host: {alert.get('agent_host', 'unknown')}\n"
            f"Source: {alert.get('log_source', '-')}\n"
            f"Type: {alert.get('alert_type', '-')}\n"
            f"Severity: {alert.get('severity', '-').upper()}\n"
            f"Description: {alert.get('description', '-')}\n"
            f"--------------------\n"
            f"{detail_str}"
        )
        try:
            r = httpx.post(url, json={
                "chat_id": self.telegram_chat_id,
                "text":    plain_msg,
            }, timeout=10)
            if r.is_success:
                logger.info(f"Telegram sent (plain fallback): alert #{alert_id}")
            else:
                logger.error(f"Telegram plain fallback also failed: {r.text}")
        except Exception as e:
            logger.error(f"Telegram plain send failed: {e}")

    def _send_discord(self, alert: dict, alert_id: int):
        severity  = alert.get("severity", "low")
        color_map = {"low": 3447003, "medium": 16776960, "high": 15158332, "critical": 10038562}
        emoji     = SEVERITY_EMOJI.get(severity, "⚪")
        details   = alert.get("details", {}) or {}

        payload = {
            "embeds": [{
                "title":       f"{emoji} Alert #{alert_id}: {alert.get('alert_type', '-')}",
                "description": str(alert.get("description", "-"))[:2000],
                "color":       color_map.get(severity, 3447003),
                "fields": [
                    {"name": "Host",     "value": f"`{alert.get('agent_host', 'unknown')}`", "inline": True},
                    {"name": "Source",   "value": f"`{alert.get('log_source', '-')}`",       "inline": True},
                    {"name": "Severity", "value": f"**{severity.upper()}**",                  "inline": True},
                ] + [
                    {"name": str(k)[:256], "value": str(v)[:1024], "inline": True}
                    for k, v in details.items()
                ][:20],  # Discord max 25 fields
                "footer": {"text": "Blueteam Monitor"},
            }]
        }
        try:
            r = httpx.post(self.discord_webhook, json=payload, timeout=10)
            if not r.is_success:
                logger.error(f"Discord error: {r.text}")
            else:
                logger.info(f"Discord sent: alert #{alert_id}")
        except Exception as e:
            logger.error(f"Discord send failed: {e}")
