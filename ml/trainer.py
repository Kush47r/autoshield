"""
ml/trainer.py
─────────────
Trains a Random Forest classifier on the unified threat data and saves
the model to ml/models/.

Usage:
    python ml/trainer.py                        # train from threats_latest.parquet
    python ml/trainer.py --data path/to/file.parquet
    python ml/trainer.py --min-records 100
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.features import engineer_features, get_labels, feature_names, INT_TO_SEVERITY, SEVERITY_ORDER
from utils.logger import get_logger

logger = get_logger("Trainer")

MODELS_DIR   = Path(__file__).parent / "models"
DEFAULT_DATA = Path(__file__).parent.parent / "data" / "processed" / "threats_latest.parquet"
MIN_RECORDS  = 50


def train(data_path: Path = DEFAULT_DATA, min_records: int = MIN_RECORDS) -> dict:
    """
    Full training pipeline.
    Returns a metrics dict summarising the run.
    """
    logger.info("=" * 55)
    logger.info("   AutoShield — RF Trainer")
    logger.info("=" * 55)

    # ── Load data ──────────────────────────────────────────────
    if not data_path.exists():
        logger.error(f"Data file not found: {data_path}")
        logger.error("Run pipeline.py first to generate threat data.")
        return {"status": "failed", "reason": "data file missing"}

    df = pd.read_parquet(data_path)
    logger.info(f"Loaded {len(df)} records from {data_path.name}")

    if len(df) < min_records:
        logger.warning(f"Only {len(df)} records — need ≥{min_records} to train. Skipping.")
        return {"status": "skipped", "reason": "insufficient data", "records": len(df)}

    # ── Feature engineering ────────────────────────────────────
    X = engineer_features(df)
    y = get_labels(df)

    logger.info(f"Features: {X.shape[1]} columns, {len(y)} samples")
    logger.info(f"Class distribution: {y.value_counts().sort_index().to_dict()}")

    # ── Train / test split ─────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    # ── Class weights (handles imbalanced data) ────────────────
    classes = np.unique(y_train)
    weights = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight_map = dict(zip(classes.tolist(), weights.tolist()))

    # ── Train Random Forest ────────────────────────────────────
    logger.info("Training Random Forest …")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight=class_weight_map,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    logger.info("Training complete.")

    # ── Evaluate ───────────────────────────────────────────────
    y_pred = rf.predict(X_test)

    target_names = [INT_TO_SEVERITY[i] for i in sorted(INT_TO_SEVERITY)]
    report = classification_report(
        y_test, y_pred,
        target_names=target_names,
        labels=list(range(len(SEVERITY_ORDER))),
        zero_division=0,
        output_dict=True,
    )
    accuracy = report["accuracy"]
    logger.info(f"Test accuracy: {accuracy:.3f}")
    logger.info("\n" + classification_report(
        y_test, y_pred,
        target_names=target_names,
        labels=list(range(len(SEVERITY_ORDER))),
        zero_division=0,
    ))

    # ── Cross-validation (5-fold) ──────────────────────────────
    cv_scores = cross_val_score(rf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
    logger.info(f"5-fold CV accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # ── Feature importance (top 10) ────────────────────────────
    feat_names = feature_names()
    importances = pd.Series(rf.feature_importances_, index=feat_names)
    top10 = importances.nlargest(10)
    logger.info("Top 10 features:\n" + top10.to_string())

    # ── Save model ─────────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    model_path = MODELS_DIR / f"rf_threat_classifier_{ts}.joblib"
    latest_path = MODELS_DIR / "rf_threat_classifier_latest.joblib"

    joblib.dump(rf, model_path)
    joblib.dump(rf, latest_path)
    logger.info(f"Model saved → {model_path}")
    logger.info(f"Latest model → {latest_path}")

    # ── Save metadata ──────────────────────────────────────────
    metrics = {
        "trained_at":     ts,
        "data_file":      str(data_path),
        "records_total":  len(df),
        "records_train":  len(X_train),
        "records_test":   len(X_test),
        "test_accuracy":  round(accuracy, 4),
        "cv_mean":        round(float(cv_scores.mean()), 4),
        "cv_std":         round(float(cv_scores.std()), 4),
        "class_report":   report,
        "top_features":   top10.to_dict(),
        "model_path":     str(model_path),
    }

    meta_path = MODELS_DIR / "metrics.json"
    with open(meta_path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics saved → {meta_path}")

    logger.info("=" * 55)
    logger.info(f"   Done. Accuracy: {accuracy:.3f}  |  CV: {cv_scores.mean():.3f}")
    logger.info("=" * 55)

    return {"status": "success", **metrics}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AutoShield RF classifier")
    parser.add_argument("--data",        type=Path, default=DEFAULT_DATA, help="Path to parquet file")
    parser.add_argument("--min-records", type=int,  default=MIN_RECORDS,  help="Minimum records to proceed")
    args = parser.parse_args()

    result = train(data_path=args.data, min_records=args.min_records)
    print(json.dumps(result, indent=2, default=str))
