"""
Autonomous Kafka-based pipeline.

Each extractor runs on its own schedule, publishes raw records to its
Kafka topic, and three background consumers handle the rest:
  - StreamProcessor  : raw → normalized (threat.normalized)
  - StorageConsumer  : normalized → Parquet / JSON / SQLite (batched)
  - AlertConsumer    : critical/high records → logs/alerts.jsonl

Run modes:
  python streaming/kafka_pipeline.py              # continuous, all sources
  python streaming/kafka_pipeline.py --run-once   # one shot then exit
  python streaming/kafka_pipeline.py --sources otx nvd
"""

import sys
import time
import signal
import threading
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import settings
from utils.logger import get_logger
from extractors.abuseipdb import AbuseIPDBExtractor
from extractors.otx import OTXExtractor
from extractors.virustotal import VirusTotalExtractor
from extractors.nvd import NVDExtractor
from streaming.producer import ThreatProducer
from streaming.stream_processor import StreamProcessor
from streaming.storage_consumer import StorageConsumer
from streaming.alert_consumer import AlertConsumer
from streaming.topics import SOURCE_TO_TOPIC

logger = get_logger("KafkaPipeline")

EXTRACTORS = {
    "abuseipdb":  AbuseIPDBExtractor,
    "otx":        OTXExtractor,
    "virustotal": VirusTotalExtractor,
    "nvd":        NVDExtractor,
}

# Independent run cadence per source (seconds)
EXTRACT_INTERVALS = {
    "abuseipdb":  3600,    # every 1 hour
    "otx":        1800,    # every 30 min — highest volume source
    "virustotal": 7200,    # every 2 hours
    "nvd":        21600,   # every 6 hours — CVEs don't change that fast
}


def _run_extractor_loop(name: str, ExtractorClass, producer: ThreatProducer, interval: int):
    topic = SOURCE_TO_TOPIC[name]
    logger.info(f"Extractor [{name}] started — interval: {interval}s")
    while True:
        try:
            df = ExtractorClass().run()
            if not df.empty:
                producer.publish_dataframe(df, topic)
        except Exception as e:
            logger.error(f"Extractor [{name}] error: {e}")
        time.sleep(interval)


def start(sources: list = None, run_once: bool = False):
    logger.info("=" * 55)
    logger.info("   AutoShield Kafka Pipeline Starting")
    logger.info(f"   {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    logger.info("   Mode: " + ("run-once" if run_once else "continuous"))
    logger.info("=" * 55)

    # Start downstream consumers first
    stream_proc = StreamProcessor()
    storage_con = StorageConsumer()
    alert_con   = AlertConsumer()

    stream_proc.start_async()
    storage_con.start_async()
    alert_con.start_async()

    logger.info("Consumers online. Waiting 3s before extractors start...")
    time.sleep(3)

    active = {k: v for k, v in EXTRACTORS.items() if not sources or k in sources}
    producer = ThreatProducer()

    if run_once:
        logger.info(f"Run-once mode — extracting from: {list(active.keys())}")
        for name, ExtractorClass in active.items():
            topic = SOURCE_TO_TOPIC[name]
            try:
                df = ExtractorClass().run()
                if not df.empty:
                    producer.publish_dataframe(df, topic)
            except Exception as e:
                logger.error(f"[{name}] failed: {e}")
        producer.flush()
        logger.info("All extractions done. Waiting 15s for consumers to drain...")
        time.sleep(15)
        stream_proc.stop()
        storage_con.stop()
        alert_con.stop()
        return

    # Continuous mode — each extractor runs in its own thread
    threads = []
    for name, ExtractorClass in active.items():
        interval = EXTRACT_INTERVALS.get(name, 3600)
        t = threading.Thread(
            target=_run_extractor_loop,
            args=(name, ExtractorClass, producer, interval),
            daemon=True,
            name=f"Extractor-{name}",
        )
        t.start()
        threads.append(t)

    logger.info(f"{len(threads)} extractor threads running autonomously. Ctrl+C to stop.")

    def _shutdown(sig, frame):
        logger.info("Shutdown signal received — stopping consumers...")
        stream_proc.stop()
        storage_con.stop()
        alert_con.stop()
        producer.close()
        logger.info("Kafka pipeline stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        time.sleep(60)
        alive = [t.name for t in threads if t.is_alive()]
        logger.info(f"Active extractor threads: {alive}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AutoShield Kafka Pipeline")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=list(EXTRACTORS.keys()),
        default=None,
        help="Run specific sources only. Default: all.",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Extract once from all sources then exit.",
    )
    args = parser.parse_args()

    start(sources=args.sources, run_once=args.run_once)
