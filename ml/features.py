import pandas as pd

# Categorical value sets — must stay in sync with trainer & predictor
INDICATOR_TYPES = ["ip", "domain", "url", "file_hash", "cve", "unknown"]
SOURCES         = ["abuseipdb", "otx", "virustotal", "nvd"]
THREAT_TYPES    = ["malware", "phishing", "botnet", "vulnerability", "suspicious", "apt"]
TOP_COUNTRIES   = ["US", "CN", "RU", "DE", "NL", "FR", "GB", "KR", "BR", "IN", "UA", "IR"]
TAG_KEYWORDS    = ["malware", "phishing", "botnet", "ransomware", "apt", "trojan", "spyware", "c2", "exploit"]

SEVERITY_ORDER  = ["info", "low", "medium", "high", "critical"]
SEVERITY_TO_INT = {s: i for i, s in enumerate(SEVERITY_ORDER)}
INT_TO_SEVERITY = {i: s for i, s in enumerate(SEVERITY_ORDER)}


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Converts unified-schema DataFrame → numeric feature matrix.
    Every column is numeric so sklearn can consume it directly.
    """
    f = pd.DataFrame(index=df.index)

    # ── Numeric ────────────────────────────────────────────────
    f["severity_score"] = pd.to_numeric(df["severity_score"], errors="coerce").fillna(0.0)

    # ── One-hot: indicator type ────────────────────────────────
    for t in INDICATOR_TYPES:
        f[f"type_{t}"] = (df["indicator_type"] == t).astype(int)

    # ── One-hot: source ────────────────────────────────────────
    for s in SOURCES:
        f[f"source_{s}"] = (df["source"] == s).astype(int)

    # ── One-hot: threat type ───────────────────────────────────
    for t in THREAT_TYPES:
        f[f"threat_{t}"] = (df["threat_type"] == t).astype(int)

    # ── One-hot: country (top N + other) ──────────────────────
    for c in TOP_COUNTRIES:
        f[f"country_{c}"] = (df["country"] == c).astype(int)
    f["country_other"] = (
        ~df["country"].isin(TOP_COUNTRIES)
        & df["country"].notna()
        & (df["country"] != "")
    ).astype(int)
    f["has_country"] = (df["country"].notna() & (df["country"] != "")).astype(int)

    # ── Tag binary flags ───────────────────────────────────────
    tags_lower = df["tags"].fillna("").str.lower()
    for kw in TAG_KEYWORDS:
        f[f"tag_{kw}"] = tags_lower.str.contains(kw, na=False).astype(int)

    # ── Description richness (0–1) ─────────────────────────────
    f["desc_length"] = df["description"].fillna("").str.len().clip(0, 500) / 500.0

    return f


def get_labels(df: pd.DataFrame) -> pd.Series:
    """Returns severity as integers (0=info … 4=critical)."""
    return df["severity"].map(SEVERITY_TO_INT).fillna(0).astype(int)


def feature_names() -> list:
    names  = ["severity_score"]
    names += [f"type_{t}"     for t in INDICATOR_TYPES]
    names += [f"source_{s}"   for s in SOURCES]
    names += [f"threat_{t}"   for t in THREAT_TYPES]
    names += [f"country_{c}"  for c in TOP_COUNTRIES]
    names += ["country_other", "has_country"]
    names += [f"tag_{kw}"     for kw in TAG_KEYWORDS]
    names += ["desc_length"]
    return names
