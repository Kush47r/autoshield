import json
import threading
import pandas as pd
from kafka import KafkaConsumer
from config.settings import settings
from utils.logger import get_logger
from loaders.storage import DataLoader
from streaming.topics import NORMALIZED

logger = get_logger("StorageConsumer")

BATCH_SIZE = 500


class StorageConsumer:
    """
    Accumulates normalized threat records from threat.normalized and
    flushes them to Parquet / JSON / SQLite in configurable batches.
    """

    def __init__(self, batch_size: int = BATCH_SIZE):
        self._consumer = KafkaConsumer(
            NORMALIZED,
            bootstrap_servers=settings.KAFKA_BROKERS,
            group_id="storage-consumer",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        self._loader = DataLoader()
        self._buffer: list = []
        self._batch_size = batch_size
        self._running = False

    def _flush(self):
        if not self._buffer:
            return
        df = pd.DataFrame(self._buffer)
        self._loader.save(df)
        logger.info(f"Flushed {len(self._buffer)} records to storage")
        self._buffer.clear()

    def start(self):
        self._running = True
        logger.info(f"StorageConsumer started — batch size: {self._batch_size}")
        for msg in self._consumer:
            if not self._running:
                break
            self._buffer.append(msg.value)
            if len(self._buffer) >= self._batch_size:
                self._flush()
        self._flush()
        self._consumer.close()

    def start_async(self) -> threading.Thread:
        t = threading.Thread(target=self.start, daemon=True, name="StorageConsumer")
        t.start()
        return t

    def stop(self):
        self._running = False
