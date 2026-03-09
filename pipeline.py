# pipeline.py
# Master orchestrator — runs the full Extract → Transform → Load cycle
# This is the only file you need to run to execute the entire pipeline

import json
import sys
import traceback
from datetime import datetime
from pathlib import Path

# Add project root to Python path so all imports work
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import settings
from utils.logger import get_logger
from extractors.abuseipdb import AbuseIPDBExtractor
from extractors.otx import OTXExtractor
from extractors.virustotal import VirusTotalExtractor
from extractors.nvd import NVDExtractor
from transformers.normalizer import normalize_all
from loaders.storage import DataLoader

logger = get_logger("Pipeline")


def run_pipeline(sources: list = None) -> dict:
    """
    Runs the full ETL pipeline.

    Args:
        sources: which sources to run. None means all.
                 e.g. ['abuseipdb', 'nvd'] runs only those two.

    Returns:
        A summary dict with stats about the run.
    """

    run_start = datetime.utcnow()

    logger.info("=" * 55)
    logger.info("   AutoShield Pipeline Starting")
    logger.info(f"   {run_start.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    logger.info("=" * 55)

    # --- Check for missing API keys ---
    missing = settings.validate()
    if missing:
        logger.warning(f"Missing API keys: {missing} — those sources will be skipped.")

    # ── STEP 1: EXTRACT ───────────────────────────────────────
    # Map source names to their extractor classes
    all_extractors = {
        "abuseipdb":  AbuseIPDBExtractor,
        "otx":        OTXExtractor,
        "virustotal": VirusTotalExtractor,
        "nvd":        NVDExtractor,
    }

    # If specific sources were requested, only run those
    if sources:
        active = {k: v for k, v in all_extractors.items() if k in sources}
    else:
        active = all_extractors

    logger.info(f"Running extractors: {list(active.keys())}")
    logger.info("-" * 55)

    raw_data = {}
    errors   = {}

    for name, ExtractorClass in active.items():
        try:
            extractor    = ExtractorClass()
            raw_data[name] = extractor.run()
        except Exception as e:
            logger.error(f"Extractor [{name}] failed: {e}")
            errors[name]   = str(e)
            raw_data[name] = None

    # ── STEP 2: TRANSFORM ─────────────────────────────────────
    logger.info("-" * 55)
    logger.info("Normalizing data from all sources...")

    try:
        clean_df = normalize_all(raw_data)
        logger.info(f"Normalization complete — {len(clean_df)} unified records")
    except Exception as e:
        logger.critical(f"Normalization failed: {e}")
        traceback.print_exc()
        return {"status": "failed", "error": str(e)}

    # ── STEP 3: LOAD ──────────────────────────────────────────
    logger.info("-" * 55)
    logger.info("Saving data to storage...")

    try:
        loader  = DataLoader()
        saved   = loader.save(clean_df)
        stats   = loader.get_stats(clean_df)
    except Exception as e:
        logger.critical(f"Loading failed: {e}")
        traceback.print_exc()
        return {"status": "failed", "error": str(e)}

    # ── STEP 4: SUMMARY ───────────────────────────────────────
    run_end  = datetime.utcnow()
    duration = round((run_end - run_start).total_seconds(), 2)

    summary = {
        "status":           "success",
        "run_start":        run_start.isoformat(),
        "run_end":          run_end.isoformat(),
        "duration_seconds": duration,
        "sources_run":      list(active.keys()),
        "errors":           errors,
        "stats":            stats,
        "files":            saved,
    }

    logger.info("=" * 55)
    logger.info("   Pipeline Complete!")
    logger.info(f"   Duration:         {duration}s")
    logger.info(f"   Total records:    {stats.get('total_records', 0)}")
    logger.info(f"   Critical threats: {stats.get('critical_count', 0)}")
    logger.info(f"   High threats:     {stats.get('high_count', 0)}")
    logger.info(f"   Avg score:        {stats.get('avg_score', 0)}")
    logger.info("=" * 55)

    # Save run summary to logs/run_history.json
    _save_run_history(summary)

    return summary


def _save_run_history(summary: dict):
    """
    Keeps a log of the last 30 pipeline runs.
    Useful for spotting patterns — is the pipeline
    getting more threats over time? Are errors increasing?
    """
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
    history_file = settings.LOG_DIR / "run_history.json"

    # Load existing history
    history = []
    if history_file.exists():
        try:
            with open(history_file) as f:
                history = json.load(f)
        except Exception:
            history = []

    # Add this run
    history.append(summary)

    # Keep only last 30 runs
    history = history[-30:]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)

    logger.info(f"Run history saved → {history_file}")


# ── ENTRY POINT ───────────────────────────────────────────────
# This block only runs when you execute pipeline.py directly
# It won't run if another file imports from pipeline.py

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AutoShield Data Pipeline")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["abuseipdb", "otx", "virustotal", "nvd"],
        help="Run specific sources only. Default: all.",
        default=None,
    )
    args = parser.parse_args()

    result = run_pipeline(sources=args.sources)

    print("\n📊 Pipeline Summary:")
    print(json.dumps(result, indent=2, default=str))