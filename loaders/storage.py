# loaders/storage.py

import json
import pandas as pd
from pathlib import Path
from datetime import datetime
from utils.logger import get_logger
from config.settings import settings

logger = get_logger("Loader")


class DataLoader:
    """
    Saves normalized threat data to 3 formats:
    1. Parquet — for the ML team (fast, compressed, typed)
    2. JSON    — for debugging and sharing
    3. SQLite  — for historical queries
    """

    def __init__(self):
        # Make sure output folders exist
        # exist_ok=True means don't crash if folder already exists
        settings.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        settings.RAW_DIR.mkdir(parents=True, exist_ok=True)
        settings.LOG_DIR.mkdir(parents=True, exist_ok=True)

    def save(self, df: pd.DataFrame) -> dict:
        """
        Master save method — saves to all formats.
        Returns a summary of what was saved.
        """
        if df.empty:
            logger.warning("No data to save — DataFrame is empty.")
            return {"saved": 0}

        # Timestamp for this run — used in filenames
        run_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # Save to each format
        self._save_parquet(df, run_ts)
        self._save_json(df, run_ts)
        self._save_sqlite(df)

        summary = {
            "total_saved":   len(df),
            "run_timestamp": run_ts,
            "parquet_path":  str(settings.PROCESSED_DIR / f"threats_{run_ts}.parquet"),
            "json_path":     str(settings.PROCESSED_DIR / f"threats_{run_ts}.json"),
        }

        logger.info(f"Save complete — {len(df)} records written.")
        return summary

    def _save_parquet(self, df: pd.DataFrame, run_ts: str):
        """
        Parquet is a binary column-based format.
        Much faster and smaller than CSV for large datasets.
        This is what the ML team reads.
        """
        # Timestamped file — keeps history of every run
        path = settings.PROCESSED_DIR / f"threats_{run_ts}.parquet"
        df.to_parquet(path, index=False)
        logger.info(f"Parquet saved → {path}")

        # Also save a 'latest' file — fixed path the ML team always reads
        latest = settings.PROCESSED_DIR / "threats_latest.parquet"
        df.to_parquet(latest, index=False)
        logger.info(f"Latest Parquet updated → {latest}")

    def _save_json(self, df: pd.DataFrame, run_ts: str):
        """
        JSON snapshot — human readable, easy to inspect.
        Good for debugging and sharing with teammates.
        """
        path = settings.PROCESSED_DIR / f"threats_{run_ts}.json"
        df.to_json(path, orient="records", indent=2)
        logger.info(f"JSON saved → {path}")

    def _save_sqlite(self, df: pd.DataFrame):
        """
        SQLite is a lightweight database stored as a single file.
        Good for historical queries — you can query across all runs.
        No server needed — it's just a file.
        """
        try:
            # Only import sqlalchemy when needed
            from sqlalchemy import create_engine

            db_path = settings.DATA_DIR / "autoshield.db"
            engine  = create_engine(f"sqlite:///{db_path}")

            # if_exists='append' adds to existing data
            # if_exists='replace' would wipe previous data
            df.to_sql(
                "threats",
                engine,
                if_exists="append",
                index=False
            )
            logger.info(f"SQLite saved → {db_path}")

        except Exception as e:
            # If SQLite fails, don't crash the whole pipeline
            # Parquet and JSON are already saved
            logger.warning(f"SQLite save failed (non-critical): {e}")

    def get_stats(self, df: pd.DataFrame) -> dict:
        """
        Generates a summary of what's in the data.
        Useful for logging and reports.
        """
        if df.empty:
            return {}

        return {
            "total_records":     len(df),
            "by_source":         df["source"].value_counts().to_dict(),
            "by_severity":       df["severity"].value_counts().to_dict(),
            "by_indicator_type": df["indicator_type"].value_counts().to_dict(),
            "by_threat_type":    df["threat_type"].value_counts().to_dict(),
            "critical_count":    int(df[df["severity"] == "critical"].shape[0]),
            "high_count":        int(df[df["severity"] == "high"].shape[0]),
            "avg_score":         round(float(df["severity_score"].mean()), 2),
        }


