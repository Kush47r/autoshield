# streaming/stream_processor.py

import json
import threading
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
from config.settings import settings
from utils.logger import get_logger
from transformers.normalizer import (
    normalize_abuseipdb,
    normalize_otx,
    normalize_virustotal,
    normalize_nvd,
)
from streaming.topics import (
    RAW_ABUSEIPDB, RAW_OTX, RAW_VIRUSTOTAL, RAW_NVD,
    NORMALIZED, ALL_RAW_TOPICS,
)

logger = get_logger("StreamProcessor")

# ML teammate listens to this topic
LIVE_FEED = "autoshield-live-feed"

TOPIC_NORMALIZER_MAP = {
    RAW_ABUSEIPDB:  normalize_abuseipdb,
    RAW_OTX:        normalize_otx,
    RAW_VIRUSTOTAL: normalize_virustotal,
    RAW_NVD:        normalize_nvd,
}


class StreamProcessor:
    """
    Subscribes to all raw threat topics, normalizes each record,
    and publishes to both:
      - threat.normalized      (your storage consumer reads this)
      - autoshield-live-feed   (ML teammate's model reads this)
    """

    def __init__(self):
        self._consumer = KafkaConsumer(
            *ALL_RAW_TOPICS,
            bootstrap_servers=settings.KAFKA_BROKERS,
            group_id="stream-processor",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        self._producer = KafkaProducer(
            bootstrap_servers=settings.KAFKA_BROKERS,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            retries=3,
        )
        self._running = False

    def _process(self, topic: str, raw_record: dict):
        normalizer = TOPIC_NORMALIZER_MAP.get(topic)
        if not normalizer:
            return

        df            = pd.DataFrame([raw_record])
        normalized_df = normalizer(df)

        for _, row in normalized_df.iterrows():
            record = row.to_dict()

            # Publish to storage consumer
            self._producer.send(NORMALIZED, value=record)

            # Also publish to ML teammate's topic
            self._producer.send(LIVE_FEED, value=record)

    def start(self):
        self._running = True
        logger.info("StreamProcessor started — publishing to threat.normalized + autoshield-live-feed")
        for msg in self._consumer:
            if not self._running:
                break
            try:
                self._process(msg.topic, msg.value)
            except Exception as e:
                logger.error(f"Error processing record from [{msg.topic}]: {e}")
        self._producer.flush()
        self._consumer.close()
        self._producer.close()

    def start_async(self) -> threading.Thread:
        t = threading.Thread(target=self.start, daemon=True, name="StreamProcessor")
        t.start()
        return t

    def stop(self):
        self._running = False