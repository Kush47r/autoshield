import json
import pandas as pd
from kafka import KafkaProducer
from config.settings import settings
from utils.logger import get_logger

logger = get_logger("ThreatProducer")


class ThreatProducer:
    def __init__(self):
        self._producer = KafkaProducer(
            bootstrap_servers=settings.KAFKA_BROKERS,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            retries=3,
        )

    def publish_dataframe(self, df: pd.DataFrame, topic: str, key_column: str = None) -> int:
        count = 0
        for _, row in df.iterrows():
            record = row.to_dict()
            key = str(record.get(key_column)) if key_column else None
            self._producer.send(topic, value=record, key=key)
            count += 1
        self._producer.flush()
        logger.info(f"Published {count} records to [{topic}]")
        return count

    def publish(self, record: dict, topic: str, key: str = None):
        self._producer.send(topic, value=record, key=key)

    def flush(self):
        self._producer.flush()

    def close(self):
        self._producer.close()
