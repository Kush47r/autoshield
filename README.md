# 🛡️ AutoShield — Adaptive Threat Intelligence Pipeline

AutoShield is a production-ready data pipeline that automatically extracts threat intelligence from multiple cybersecurity sources daily, normalizes it into a unified schema, and delivers clean structured data for machine learning models to detect threats and update firewall rules.

---

## 🏗️ Project Architecture

```
[AbuseIPDB]  [AlienVault OTX]  [VirusTotal]  [NVD/CVE]
      │               │               │             │
      └───────────────┴───────────────┴─────────────┘
                              │
                        ┌─────▼──────┐
                        │  EXTRACT   │  extractors/
                        │ fetch raw  │
                        │    data    │
                        └─────┬──────┘
                              │
                        ┌─────▼──────┐
                        │ TRANSFORM  │  transformers/
                        │ clean and  │
                        │   unify    │
                        └─────┬──────┘
                              │
                        ┌─────▼──────┐
                        │   LOAD     │  loaders/
                        │  Parquet   │
                        │  JSON      │
                        │  SQLite    │
                        └─────┬──────┘
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
           ML Models      Firewall    Analysts
           (read Parquet)  (read ML   (read JSON)
                           output)
```

---

## 📁 Project Structure

```
autoshield/
│
├── pipeline.py                 ← Master orchestrator (run this)
│
├── config/
│   └── settings.py             ← Loads all config from .env
│
├── extractors/
│   ├── base.py                 ← Shared base class for all extractors
│   ├── abuseipdb.py            ← Malicious IP reports
│   ├── otx.py                  ← AlienVault OTX multi-threat feed
│   ├── virustotal.py           ← Malware & malicious domains
│   └── nvd.py                  ← CVE vulnerability feed (NIST)
│
├── transformers/
│   └── normalizer.py           ← Unifies all sources into one schema
│
├── loaders/
│   └── storage.py              ← Saves to Parquet, JSON, SQLite
│
├── schedulers/
│   └── scheduler.py            ← Daily automatic execution
│
├── utils/
│   └── logger.py               ← Centralized logging system
│
├── data/
│   ├── raw/                    ← Raw API responses (per run)
│   └── processed/              ← Clean unified output
│       ├── threats_latest.parquet   ← ML team reads this
│       └── threats_YYYYMMDD.json    ← Daily snapshots
│
├── logs/
│   ├── pipeline_YYYYMMDD.log   ← Detailed run logs
│   └── run_history.json        ← Last 30 run summaries
│
├── .env.example                ← API key template (copy to .env)
└── requirements.txt            ← Python dependencies
```

---

## ⚡ Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/Kush47r/autoshield.git
cd autoshield
git checkout pipeline   # or ml-models / firewall for your branch
```

### 2. Set up virtual environment

```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
```

### 3. Configure API keys

```bash
copy .env.example .env       # Windows
cp .env.example .env         # Mac/Linux
```

Open `.env` and fill in your keys:

```
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
NVD_API_KEY=                    # leave empty, no key needed
```

### 4. Run the pipeline

```bash
python pipeline.py
```

---

## 🔧 Usage

### Run all sources
```bash
python pipeline.py
```

### Run specific sources only
```bash
python pipeline.py --sources abuseipdb nvd
python pipeline.py --sources otx virustotal
```

### Run on a schedule (daily at 2AM UTC)
```bash
python schedulers/scheduler.py --time 02:00
```

### Run immediately via scheduler
```bash
python schedulers/scheduler.py --run-now
```

---

## 📊 Data Sources

| Source | Type | Records/Run | API Key Required |
|--------|------|-------------|-----------------|
| AbuseIPDB | Malicious IPs | ~100 | ✅ Free |
| AlienVault OTX | Multi-threat indicators | ~7000 | ✅ Free |
| VirusTotal | Malware / domains | ~10 | ✅ Free |
| NVD / CVE | Vulnerabilities | ~50 | ❌ Not needed |

### Get Free API Keys

| Source | Sign Up URL |
|--------|------------|
| AbuseIPDB | https://www.abuseipdb.com/register |
| AlienVault OTX | https://otx.alienvault.com |
| VirusTotal | https://www.virustotal.com/gui/join-us |
| NVD | Not required |

---

## 📐 Unified Data Schema

Every record — regardless of source — is normalized to this schema:

| Column | Type | Description |
|--------|------|-------------|
| `record_id` | str | Unique identifier |
| `source` | str | abuseipdb / otx / virustotal / nvd |
| `indicator_type` | str | ip / domain / url / file_hash / cve |
| `indicator_value` | str | The actual IOC (IP, domain, CVE ID) |
| `threat_type` | str | malware / phishing / botnet / vulnerability / suspicious |
| `severity` | str | critical / high / medium / low / info |
| `severity_score` | float | 0.0 – 10.0 normalized score |
| `country` | str | Country code (e.g. US, CN, RU) |
| `tags` | str | Comma-separated tags |
| `description` | str | Human-readable description |
| `first_seen` | str | ISO timestamp |
| `last_seen` | str | ISO timestamp |
| `pipeline_timestamp` | str | When this pipeline run collected it |

---

## 🤝 For the ML Team

The pipeline saves a fresh `threats_latest.parquet` after every run.

```python
import pandas as pd

df = pd.read_parquet("data/processed/threats_latest.parquet")

print(df.shape)
print(df["severity"].value_counts())
print(df[df["severity"] == "critical"].head())
```

Key columns for model training: `indicator_value`, `severity_score`, `threat_type`, `indicator_type`, `source`.

---

## 🤝 For the Firewall Team

Read the ML team's output and update firewall rules accordingly. The pipeline guarantees the Parquet file is refreshed daily at the configured schedule time.

---

## 🗄️ Storage Options

Set `STORAGE_TYPE` in `.env`:

| Value | Description |
|-------|-------------|
| `sqlite` | Default — single file DB, good for development |
| `postgresql` | Production — set DB credentials in `.env` |

Parquet and JSON are always saved regardless of `STORAGE_TYPE`.

---

## 📅 Pipeline Run Summary Example

```
Duration:         4.54s
Total records:    7,097
Critical threats: 107
High threats:     21
Avg score:        9.03 / 10

By source:
  abuseipdb:  100
  otx:        6,944
  virustotal: 10
  nvd:        50  (7 duplicates removed)

Output:
  data/processed/threats_latest.parquet  ✅
  data/processed/threats_20260309.json   ✅
  data/autoshield.db                     ✅
  logs/run_history.json                  ✅
```

---

## 🌿 Git Branching Strategy

```
main          ← protected, stable code only
  ├── pipeline    ← data pipeline (this repo)
  ├── ml-models   ← machine learning models
  └── firewall    ← firewall rule engine
```

All changes go through Pull Requests — nobody pushes directly to `main`.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| HTTP calls | requests |
| Data processing | pandas |
| File format | Parquet (pyarrow) |
| Database | SQLite / PostgreSQL (sqlalchemy) |
| Scheduling | schedule |
| Logging | logging + colorlog |
| Retry logic | tenacity |
| Config | python-dotenv |
| Version control | Git + GitHub |

---

## 📝 License

This project is part of the AutoShield Adaptive Threat Intelligence System.
Built for educational and research purposes.
