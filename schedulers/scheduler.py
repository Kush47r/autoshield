# schedulers/scheduler.py
# Runs the pipeline automatically every day at a set time
# Keep this running in the background and it handles everything

import sys
import schedule
import time
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import get_logger
from pipeline import run_pipeline

logger = get_logger("Scheduler")


def job():
    """
    This function is called automatically every day.
    It runs the full pipeline and logs the result.
    """
    logger.info(f"⏰ Scheduled run triggered at {datetime.utcnow().isoformat()}")

    try:
        result = run_pipeline()

        if result.get("status") == "success":
            total    = result.get("stats", {}).get("total_records", 0)
            critical = result.get("stats", {}).get("critical_count", 0)
            logger.info(f"✅ Run complete — {total} records, {critical} critical threats")
        else:
            logger.error(f"❌ Run failed: {result.get('error')}")

    except Exception as e:
        logger.critical(f"💥 Unhandled error in scheduled job: {e}")


def start(run_time: str = "02:00"):
    """
    Starts the daily scheduler.

    Args:
        run_time: Time to run in 24h UTC format e.g. "02:00"
    """
    logger.info(f"🚀 Scheduler started — pipeline runs daily at {run_time} UTC")
    logger.info("Press Ctrl+C to stop.")

    # Schedule the job to run every day at run_time
    schedule.every().day.at(run_time).do(job)

    # Keep the script alive, checking every minute if it's time to run
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AutoShield Scheduler")
    parser.add_argument(
        "--time",
        default="02:00",
        help="Time to run daily in 24h UTC format e.g. 02:00"
    )
    parser.add_argument(
        "--run-now",
        action="store_true",
        help="Run pipeline immediately right now"
    )
    args = parser.parse_args()

    if args.run_now:
        logger.info("Running pipeline now (--run-now flag)...")
        job()
    else:
        start(run_time=args.time)