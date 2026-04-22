"""
ml/predictor.py
───────────────
Loads the saved Random Forest model and scores new threat data.

Adds three columns to the input DataFrame:
  predicted_severity  — severity label predicted by the model
  predicted_score     — 0-10 numeric score mapped from predicted class
  block_recommended   — True if predicted severity is high or critical
  confidence          — probability of the predicted class (0.0–1.0)

Usage:
    from ml.predictor import ThreatPredictor
    p = ThreatPredictor()
    scored_df = p.predict(df)
"""

import sys
from pathlib import Path

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.features import engineer_features, INT_TO_SEVERITY, SEVERITY_ORDER
from utils.logger import get_logger

logger = get_logger("Predictor")

MODELS_DIR   = Path(__file__).parent / "models"
LATEST_MODEL = MODELS_DIR / "rf_threat_classifier_latest.joblib"

# Severity → rough numeric score for reporting
SEVERITY_SCORE_MAP = {"info": 0.5, "low": 3.0, "medium": 5.5, "high": 8.0, "critical": 9.5}
BLOCK_SEVERITIES   = {"high", "critical"}


class ThreatPredictor:
    def __init__(self, model_path: Path = LATEST_MODEL):
        if not model_path.exists():
            raise FileNotFoundError(
                f"No trained model at {model_path}. Run: python ml/trainer.py"
            )
        self.model = joblib.load(model_path)
        logger.info(f"Model loaded from {model_path.name}")

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Scores every row in df and returns df with prediction columns appended.
        """
        if df.empty:
            logger.warning("Empty DataFrame — nothing to predict.")
            return df

        X = engineer_features(df)

        # Predicted class (int) → severity label
        y_pred   = self.model.predict(X)
        y_proba  = self.model.predict_proba(X)
        conf     = y_proba.max(axis=1)

        pred_labels  = [INT_TO_SEVERITY[c] for c in y_pred]
        pred_scores  = [SEVERITY_SCORE_MAP[lbl] for lbl in pred_labels]
        block_flags  = [lbl in BLOCK_SEVERITIES for lbl in pred_labels]

        result = df.copy()
        result["predicted_severity"] = pred_labels
        result["predicted_score"]    = pred_scores
        result["confidence"]         = conf.round(3)
        result["block_recommended"]  = block_flags

        total    = len(result)
        to_block = result["block_recommended"].sum()
        logger.info(f"Scored {total} records — {to_block} flagged for blocking "
                    f"({to_block/total*100:.1f}%)")

        return result

    def predict_from_parquet(self, parquet_path: Path) -> pd.DataFrame:
        df = pd.read_parquet(parquet_path)
        logger.info(f"Loaded {len(df)} records from {parquet_path.name}")
        return self.predict(df)

    def summary(self, scored_df: pd.DataFrame) -> dict:
        """Returns a stats dict for the scored DataFrame."""
        if "predicted_severity" not in scored_df.columns:
            return {}
        return {
            "total":             len(scored_df),
            "by_predicted_sev":  scored_df["predicted_severity"].value_counts().to_dict(),
            "block_recommended": int(scored_df["block_recommended"].sum()),
            "avg_confidence":    round(float(scored_df["confidence"].mean()), 3),
        }


if __name__ == "__main__":
    import argparse, json
    from pathlib import Path

    DEFAULT_DATA = Path(__file__).parent.parent / "data" / "processed" / "threats_latest.parquet"

    parser = argparse.ArgumentParser(description="Score threats with trained RF model")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--out",  type=Path, default=None, help="Save scored parquet here")
    args = parser.parse_args()

    predictor  = ThreatPredictor()
    scored     = predictor.predict_from_parquet(args.data)
    stats      = predictor.summary(scored)

    print(json.dumps(stats, indent=2))

    if args.out:
        scored.to_parquet(args.out, index=False)
        print(f"Scored data saved → {args.out}")
