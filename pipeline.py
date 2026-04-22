# pipeline.py
# Master orchestrator — runs the full Extract → Transform → Load → ML → Firewall cycle

import json
import sys
import traceback
from datetime import datetime
from pathlib import Path

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

SCORED_PARQUET = settings.PROCESSED_DIR / "threats_latest_scored.parquet"


def run_pipeline(sources: list = None, run_ml: bool = True, update_firewall: bool = True) -> dict:
    """
    Runs the full ETL + ML + Firewall pipeline.

    Args:
        sources:          which sources to run (None = all).
        run_ml:           score threats with the trained RF model after loading.
        update_firewall:  generate firewall block rules after ML scoring.

    Returns:
        Summary dict with stats for every stage.
    """

    run_start = datetime.utcnow()

    logger.info("=" * 55)
    logger.info("   AutoShield Pipeline Starting")
    logger.info(f"   {run_start.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    logger.info("=" * 55)

    missing = settings.validate()
    if missing:
        logger.warning(f"Missing API keys: {missing} — those sources will be skipped.")

    # ── STEP 1: EXTRACT ───────────────────────────────────────
    all_extractors = {
        "abuseipdb":  AbuseIPDBExtractor,
        "otx":        OTXExtractor,
        "virustotal": VirusTotalExtractor,
        "nvd":        NVDExtractor,
    }

    active = {k: v for k, v in all_extractors.items() if k in sources} if sources else all_extractors

    logger.info(f"Running extractors: {list(active.keys())}")
    logger.info("-" * 55)

    raw_data = {}
    errors   = {}

    for name, ExtractorClass in active.items():
        try:
            extractor      = ExtractorClass()
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
        loader = DataLoader()
        saved  = loader.save(clean_df)
        stats  = loader.get_stats(clean_df)
    except Exception as e:
        logger.critical(f"Loading failed: {e}")
        traceback.print_exc()
        return {"status": "failed", "error": str(e)}

    ml_stats       = {}
    firewall_stats = {}

    # ── STEP 4: ML SCORING ────────────────────────────────────
    if run_ml:
        logger.info("-" * 55)
        logger.info("Scoring threats with RF model...")
        try:
            from ml.predictor import ThreatPredictor
            predictor  = ThreatPredictor()
            scored_df  = predictor.predict(clean_df)
            ml_stats   = predictor.summary(scored_df)

            scored_df.to_parquet(SCORED_PARQUET, index=False)
            logger.info(f"Scored data saved → {SCORED_PARQUET}")
            logger.info(f"  Block recommended: {ml_stats.get('block_recommended', 0)} indicators")
        except FileNotFoundError:
            logger.warning("No trained model found — skipping ML scoring.")
            logger.warning("Train first: python ml/trainer.py")
            scored_df = clean_df
        except Exception as e:
            logger.error(f"ML scoring failed (non-critical): {e}")
            scored_df = clean_df

        # ── STEP 5: FIREWALL UPDATE ───────────────────────────
        if update_firewall and "block_recommended" in scored_df.columns:
            logger.info("-" * 55)
            logger.info("Updating firewall rules...")
            try:
                from ml.firewall import FirewallUpdater
                fw             = FirewallUpdater()
                firewall_stats = fw.update(scored_df)
                logger.info(f"  IPs blocked:     {firewall_stats.get('ips_blocked', 0)}")
                logger.info(f"  Domains blocked: {firewall_stats.get('domains_blocked', 0)}")
            except Exception as e:
                logger.error(f"Firewall update failed (non-critical): {e}")

    # ── SUMMARY ───────────────────────────────────────────────
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
        "ml":               ml_stats,
        "firewall":         firewall_stats,
    }

    logger.info("=" * 55)
    logger.info("   Pipeline Complete!")
    logger.info(f"   Duration:         {duration}s")
    logger.info(f"   Total records:    {stats.get('total_records', 0)}")
    logger.info(f"   Critical threats: {stats.get('critical_count', 0)}")
    logger.info(f"   High threats:     {stats.get('high_count', 0)}")
    logger.info(f"   Avg score:        {stats.get('avg_score', 0)}")
    if ml_stats:
        logger.info(f"   ML block flags:   {ml_stats.get('block_recommended', 0)}")
    if firewall_stats:
        logger.info(f"   IPs blocked:      {firewall_stats.get('ips_blocked', 0)}")
        logger.info(f"   Domains blocked:  {firewall_stats.get('domains_blocked', 0)}")
    logger.info("=" * 55)

    _save_run_history(summary)

    return summary


def _save_run_history(summary: dict):
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
    history_file = settings.LOG_DIR / "run_history.json"

    history = []
    if history_file.exists():
        try:
            with open(history_file) as f:
                history = json.load(f)
        except Exception:
            history = []

    history.append(summary)
    history = history[-30:]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)

    logger.info(f"Run history saved → {history_file}")


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
    parser.add_argument("--skip-ml",       action="store_true", help="Skip ML scoring step")
    parser.add_argument("--skip-firewall", action="store_true", help="Skip firewall update step")
    args = parser.parse_args()

    result = run_pipeline(
        sources=args.sources,
        run_ml=not args.skip_ml,
        update_firewall=not args.skip_firewall,
    )

    print("\nPipeline Summary:")
    print(json.dumps(result, indent=2, default=str))
    print("\nPipeline execution complete. Check logs for details.")
