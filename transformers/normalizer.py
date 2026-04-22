# transformers/normalizer.py

import pandas as pd
from datetime import datetime, timezone
from utils.logger import get_logger

logger = get_logger("Normalizer")

# ── THE UNIFIED SCHEMA ─────────────────────────────────────────
# This is the contract between you (pipeline) and the ML team.
# Every record from every source will have EXACTLY these columns.
# No matter where the data came from — it all looks the same after this.

UNIFIED_SCHEMA = [
    "record_id",          # unique identifier for this record
    "source",             # where it came from: abuseipdb | otx | virustotal | nvd
    "indicator_type",     # ip | domain | url | file_hash | cve
    "indicator_value",    # the actual IOC: IP address, domain, CVE ID etc.
    "threat_type",        # malware | phishing | botnet | vulnerability | suspicious
    "severity",           # critical | high | medium | low | info
    "severity_score",     # 0.0 to 10.0 — normalized number
    "country",            # country code e.g. US, CN, RU
    "tags",               # comma separated tags
    "description",        # human readable description
    "first_seen",         # when first reported
    "last_seen",          # when last seen
    "pipeline_timestamp", # when THIS pipeline run collected it
]


def _now() -> str:
    """Returns current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def _safe_score(value, default=0.0) -> float:
    """Safely converts any value to a float score."""
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return default


def _score_to_severity(score: float) -> str:
    """
    Converts a 0-10 numeric score to a severity label.
    This is the same scale used by CVSS.
    """
    if score >= 9.0:   return "critical"
    elif score >= 7.0: return "high"
    elif score >= 4.0: return "medium"
    elif score > 0.0:  return "low"
    else:              return "info"


# ── PER SOURCE NORMALIZERS ─────────────────────────────────────
# Each function below takes the raw DataFrame from one source
# and converts it to the unified schema above.

def normalize_abuseipdb(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    records = []
    for _, row in df.iterrows():
        # AbuseIPDB confidence is 0-100, convert to 0-10
        raw_score = _safe_score(row.get("confidence_score", 0)) / 10.0

        records.append({
            "record_id":          f"abuse_{row.get('ip_address', '')}",
            "source":             "abuseipdb",
            "indicator_type":     "ip",
            "indicator_value":    row.get("ip_address", ""),
            "threat_type":        "suspicious",
            "severity":           _score_to_severity(raw_score),
            "severity_score":     raw_score,
            "country":            row.get("country_code", ""),
            "tags":               "malicious-ip",
            "description":        f"Reported {row.get('total_reports', 'N/A')} times. ISP: {row.get('isp', 'N/A')}",
            "first_seen":         None,
            "last_seen":          str(row.get("last_reported_at", "")),
            "pipeline_timestamp": _now(),
        })

    return pd.DataFrame(records, columns=UNIFIED_SCHEMA)


def normalize_otx(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    # Map OTX indicator types to our unified types
    type_map = {
        "IPv4":            "ip",
        "domain":          "domain",
        "URL":             "url",
        "FileHash-MD5":    "file_hash",
        "FileHash-SHA256": "file_hash",
    }

    records = []
    for _, row in df.iterrows():
        ind_type = type_map.get(row.get("indicator_type", ""), "unknown")
        tags     = row.get("tags", "")

        records.append({
            "record_id":          f"otx_{row.get('pulse_id', '')}_{row.get('indicator', '')[:20]}",
            "source":             "otx",
            "indicator_type":     ind_type,
            "indicator_value":    row.get("indicator", ""),
            "threat_type":        _threat_from_tags(tags),
            "severity":           "medium",
            "severity_score":     5.0,
            "country":            "",
            "tags":               tags,
            "description":        f"Pulse: {row.get('pulse_name', '')}",
            "first_seen":         None,
            "last_seen":          str(row.get("pulse_modified", "")),
            "pipeline_timestamp": _now(),
        })

    return pd.DataFrame(records, columns=UNIFIED_SCHEMA)


def _threat_from_tags(tags: str) -> str:
    """Guesses threat type from OTX tags."""
    t = tags.lower()
    if "malware"    in t: return "malware"
    if "phish"      in t: return "phishing"
    if "botnet"     in t: return "botnet"
    if "ransomware" in t: return "malware"
    if "apt"        in t: return "apt"
    return "suspicious"


def normalize_virustotal(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    records = []
    for _, row in df.iterrows():
        mal   = int(row.get("malicious_count", 0))
        susp  = int(row.get("suspicious_count", 0))
        total = mal + susp + int(row.get("harmless_count", 0)) + int(row.get("undetected_count", 0))

        # Calculate what % of engines flagged it, scale to 0-10
        ratio = (mal / total) if total > 0 else 0.0
        score = round(ratio * 10, 2)

        records.append({
            "record_id":          f"vt_{row.get('indicator', '')}",
            "source":             "virustotal",
            "indicator_type":     row.get("indicator_type", "unknown"),
            "indicator_value":    row.get("indicator", ""),
            "threat_type":        "malware" if mal > 5 else "suspicious",
            "severity":           _score_to_severity(score),
            "severity_score":     score,
            "country":            row.get("country", ""),
            "tags":               row.get("tags", ""),
            "description":        f"Flagged by {mal} engines as malicious, {susp} suspicious.",
            "first_seen":         None,
            "last_seen":          str(row.get("last_analysis_date", "")),
            "pipeline_timestamp": _now(),
        })

    return pd.DataFrame(records, columns=UNIFIED_SCHEMA)


def normalize_nvd(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    # Map NVD severity strings to our unified severity labels
    severity_map = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "NONE":     "info",
    }

    records = []
    for _, row in df.iterrows():
        cvss      = _safe_score(row.get("cvss_score", 0))
        raw_sev   = str(row.get("cvss_severity", "")).upper()

        records.append({
            "record_id":          f"nvd_{row.get('cve_id', '')}",
            "source":             "nvd",
            "indicator_type":     "cve",
            "indicator_value":    row.get("cve_id", ""),
            "threat_type":        "vulnerability",
            "severity":           severity_map.get(raw_sev, _score_to_severity(cvss)),
            "severity_score":     cvss,
            "country":            "",
            "tags":               row.get("cwe", ""),
            "description":        str(row.get("description", ""))[:300],
            "first_seen":         str(row.get("published", "")),
            "last_seen":          str(row.get("last_modified", "")),
            "pipeline_timestamp": _now(),
        })

    return pd.DataFrame(records, columns=UNIFIED_SCHEMA)


# ── MASTER FUNCTION ────────────────────────────────────────────

def normalize_all(raw_data: dict) -> pd.DataFrame:
    """
    Takes a dict of {source_name: raw_dataframe}
    Returns one clean unified DataFrame.

    This is the only function the pipeline.py needs to call.
    """

    # Maps source name to its normalizer function
    normalizers = {
        "abuseipdb":  normalize_abuseipdb,
        "otx":        normalize_otx,
        "virustotal": normalize_virustotal,
        "nvd":        normalize_nvd,
    }

    frames = []

    for source, df in raw_data.items():
        if df is None or df.empty:
            logger.warning(f"No data from [{source}] — skipping.")
            continue

        normalizer = normalizers.get(source)
        if not normalizer:
            logger.warning(f"No normalizer found for [{source}]")
            continue

        normalized = normalizer(df)
        frames.append(normalized)
        logger.info(f"Normalized {len(normalized)} records from [{source}]")

    if not frames:
        logger.error("No data was normalized from any source.")
        return pd.DataFrame(columns=UNIFIED_SCHEMA)

    # Stack all sources into one big table
    combined = pd.concat(frames, ignore_index=True)

    # Remove duplicates — same indicator from same source
    before = len(combined)
    combined = combined.drop_duplicates(subset=["source", "indicator_value"])
    after   = len(combined)
    logger.info(f"Deduplication: {before} → {after} records ({before - after} removed)")

    # Sort by severity — highest threat at the top
    combined = combined.sort_values("severity_score", ascending=False).reset_index(drop=True)

    return combined