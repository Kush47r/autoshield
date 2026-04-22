import json
import threading
from datetime import datetime
from kafka import KafkaConsumer
from config.settings import settings
from utils.logger import get_logger
from streaming.topics import NORMALIZED

logger = get_logger("AlertConsumer")

ALERT_SEVERITIES = {"critical", "high"}


class AlertConsumer:
    """
    Monitors threat.normalized for critical and high severity records.
    Appends matching threats to logs/alerts.jsonl for immediate review.
    """

    def __init__(self):
        self._consumer = KafkaConsumer(
            NORMALIZED,
            bootstrap_servers=settings.KAFKA_BROKERS,
            group_id="alert-consumer",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        self._alert_file = settings.LOG_DIR / "alerts.jsonl"
        settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._running = False

    def _handle_alert(self, record: dict):
        record["alert_timestamp"] = datetime.utcnow().isoformat()
        with open(self._alert_file, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
        logger.warning(
            f"ALERT [{record.get('severity', '').upper()}] "
            f"{record.get('indicator_type')}={record.get('indicator_value')} "
            f"score={record.get('severity_score')}"
        )

    def start(self):
        self._running = True
        logger.info("AlertConsumer started — monitoring for critical/high threats")
        for msg in self._consumer:
            if not self._running:
                break
            record = msg.value
            if record.get("severity") in ALERT_SEVERITIES:
                try:
                    self._handle_alert(record)
                except Exception as e:
                    logger.error(f"Alert handling error: {e}")
        self._consumer.close()

    def start_async(self) -> threading.Thread:
        t = threading.Thread(target=self.start, daemon=True, name="AlertConsumer")
        t.start()
        return t

    def stop(self):
        self._running = False
