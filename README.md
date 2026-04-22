# 🛡️ AutoShield — Adaptive Threat Intelligence Pipeline

AutoShield is a production-ready data pipeline that automatically extracts threat intelligence from multiple cybersecurity sources, normalizes it into a unified schema, trains a Random Forest classifier to detect threats, and automatically generates firewall block rules — all in one command.

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
                        ┌─────▼──────┐
                        │ ML SCORING │  ml/
                        │ Random     │
                        │ Forest     │
                        └─────┬──────┘
                              │
                        ┌─────▼──────┐
                        │  FIREWALL  │  firewall/  +  ml/firewall.py
                        │ block_ips  │
                        │ iptables   │
                        │ hosts file │
                        └────────────┘
```

---

## 📁 Project Structure

```
autoshield/
│
├── pipeline.py                     ← Master orchestrator (run this)
│
├── config/
│   └── settings.py                 ← Loads all config from .env
│
├── extractors/
│   ├── base.py                     ← Shared base class
│   ├── abuseipdb.py                ← Malicious IP reports
│   ├── otx.py                      ← AlienVault OTX multi-threat feed
│   ├── virustotal.py               ← Malware & malicious domains
│   └── nvd.py                      ← CVE vulnerability feed (NIST)
│
├── transformers/
│   └── normalizer.py               ← Unifies all sources into one schema
│
├── loaders/
│   └── storage.py                  ← Saves to Parquet, JSON, SQLite
│
├── ml/
│   ├── features.py                 ← Feature engineering from unified schema
│   ├── trainer.py                  ← Trains Random Forest classifier
│   ├── predictor.py                ← Loads model, scores new threats
│   └── firewall.py                 ← Generates firewall rule files from predictions
│
├── firewall/
│   ├── rule_applier.py             ← Applies rules via iptables or hosts file
│   └── monitor.py                  ← Live dashboard of blocked threats & alerts
│
├── streaming/
│   ├── kafka_pipeline.py           ← Autonomous Kafka-based pipeline
│   ├── producer.py                 ← Publishes to Kafka topics
│   ├── stream_processor.py         ← Normalizes raw Kafka records
│   ├── storage_consumer.py         ← Batches records to storage
│   ├── alert_consumer.py           ← Monitors for critical/high alerts
│   └── topics.py                   ← Kafka topic definitions
│
├── schedulers/
│   └── scheduler.py                ← Daily automatic execution
│
├── utils/
│   └── logger.py                   ← Centralized logging system
│
├── data/
│   ├── raw/                        ← Raw API responses
│   ├── processed/
│   │   ├── threats_latest.parquet      ← Latest normalized data
│   │   ├── threats_latest_scored.parquet ← ML-scored output
│   │   └── threats_YYYYMMDD_HHMMSS.json ← Daily snapshots
│   └── firewall/
│       ├── block_ips.txt               ← IPs to block (one per line)
│       ├── block_domains.txt           ← Domains to block
│       ├── iptables_rules.sh           ← Ready-to-run iptables script
│       ├── hosts_block.txt             ← /etc/hosts format
│       └── firewall_rules.json         ← Full structured rules with metadata
│
├── ml/
│   └── models/
│       ├── rf_threat_classifier_latest.joblib  ← Active model
│       └── metrics.json                        ← Accuracy, CV scores, top features
│
├── logs/
│   ├── alerts.jsonl                ← High/critical threat alerts
│   ├── firewall_apply.jsonl        ← Firewall apply history
│   └── run_history.json            ← Last 30 pipeline run summaries
│
├── docker-compose.yml              ← Kafka + Zookeeper + Kafka UI
├── .env.example                    ← API key template
└── requirements.txt                ← Python dependencies
```

---

## ⚡ Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/Kush47r/autoshield.git
cd autoshield
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

Fill in your keys in `.env`:

```
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
NVD_API_KEY=                    # not required
```

### 4. Run the full pipeline

```bash
# Step 1 — Extract, transform, load (skip ML on first run)
python pipeline.py --skip-ml

# Step 2 — Train the Random Forest model
python ml/trainer.py

# Step 3 — Full pipeline: ETL + ML scoring + firewall rules
python pipeline.py
```

---

## 🔧 Usage

### Full pipeline (ETL + ML + Firewall rules)
```bash
python pipeline.py
```

### ETL only (no ML)
```bash
python pipeline.py --skip-ml
```

### ETL + ML, skip firewall update
```bash
python pipeline.py --skip-firewall
```

### Run specific sources only
```bash
python pipeline.py --sources abuseipdb nvd
python pipeline.py --sources otx virustotal
```

### Train / retrain the RF model
```bash
python ml/trainer.py
```

### Score threats manually
```bash
python ml/predictor.py
```

### Preview firewall rules (safe, no changes)
```bash
python firewall/rule_applier.py --dry-run
```

### Apply domain blocks to hosts file (run as Administrator on Windows)
```bash
python firewall/rule_applier.py --backend hosts
```

### Watch live firewall status
```bash
python firewall/monitor.py --watch
```

### Run on a schedule (daily at 2AM UTC)
```bash
python schedulers/scheduler.py --time 02:00
```

---

## 📊 Data Sources

| Source | Type | Records/Run | API Key Required |
|--------|------|-------------|-----------------|
| AbuseIPDB | Malicious IPs | ~100 | ✅ Free |
| AlienVault OTX | Multi-threat indicators | ~300–7000 | ✅ Free |
| VirusTotal | Malware / domains | ~10 | ✅ Free |
| NVD / CVE | Vulnerabilities | ~50 | ❌ Not needed |

### Get Free API Keys

| Source | URL |
|--------|-----|
| AbuseIPDB | https://www.abuseipdb.com/register |
| AlienVault OTX | https://otx.alienvault.com |
| VirusTotal | https://www.virustotal.com/gui/join-us |

---

## 📐 Unified Data Schema

Every record — regardless of source — is normalized to this schema:

| Column | Type | Description |
|--------|------|-------------|
| `record_id` | str | Unique identifier |
| `source` | str | abuseipdb / otx / virustotal / nvd |
| `indicator_type` | str | ip / domain / url / file_hash / cve |
| `indicator_value` | str | The actual IOC (IP, domain, CVE ID) |
| `threat_type` | str | malware / phishing / botnet / vulnerability / suspicious / apt |
| `severity` | str | critical / high / medium / low / info |
| `severity_score` | float | 0.0 – 10.0 normalized score |
| `country` | str | Country code (e.g. US, CN, RU) |
| `tags` | str | Comma-separated tags |
| `description` | str | Human-readable description |
| `first_seen` | str | ISO timestamp |
| `last_seen` | str | ISO timestamp |
| `pipeline_timestamp` | str | When this pipeline run collected it |

After ML scoring, three additional columns are added:

| Column | Type | Description |
|--------|------|-------------|
| `predicted_severity` | str | RF model severity prediction |
| `confidence` | float | Model confidence 0.0–1.0 |
| `block_recommended` | bool | True if predicted high or critical |

---

## 🤖 Machine Learning

AutoShield trains a **Random Forest classifier** on the normalized threat data.

**Model performance (on real data):**
- Test accuracy: **97.9%**
- 5-fold CV accuracy: **98.1% ± 1.2%**
- Avg prediction confidence: **95.9%**

**Top features the model uses:**

| Feature | Importance |
|---------|-----------|
| severity_score | 24.2% |
| desc_length | 13.0% |
| source_otx | 10.8% |
| source_abuseipdb | 7.4% |
| source_virustotal | 7.3% |
| type_ip | 5.9% |

The model scores every indicator and flags high/critical threats for firewall blocking. Retrain anytime with `python ml/trainer.py` — the model auto-saves to `ml/models/`.

---

## 🔥 Firewall Integration

After ML scoring, AutoShield automatically generates block rules:

| Output file | Used for |
|-------------|---------|
| `data/firewall/block_ips.txt` | IP blocklist (ipset / denyhosts) |
| `data/firewall/iptables_rules.sh` | Linux iptables DROP rules (run as root) |
| `data/firewall/hosts_block.txt` | Domain sink-hole via /etc/hosts |
| `data/firewall/firewall_rules.json` | Structured rules with full metadata |

**From a recent run:**
```
Total records scored:   482
Flagged for blocking:   140  (29.0%)
IPs blocked:            99
Domains blocked:        0
By severity:            critical=100, high=40
By source:              abuseipdb=100, nvd=40
```

---

## 📅 Pipeline Run Summary Example

```
Duration:         178s
Total records:    482
Critical threats: 100
High threats:     38
Avg score:        6.16 / 10

ML scoring:
  Block recommended: 140 indicators
  Avg confidence:    95.9%

Firewall:
  IPs blocked:     99
  Domains blocked: 0

Output files:
  data/processed/threats_latest.parquet         ✅
  data/processed/threats_latest_scored.parquet  ✅
  data/processed/threats_20260422_105707.json   ✅
  data/autoshield.db                            ✅
  data/firewall/firewall_rules.json             ✅
  data/firewall/iptables_rules.sh               ✅
  logs/run_history.json                         ✅
```

---

## 🌊 Kafka Streaming (Optional)

For continuous real-time ingestion, AutoShield includes a full Kafka pipeline.

### Start Kafka infrastructure
```bash
docker-compose up -d
```

### Run the autonomous streaming pipeline
```bash
python streaming/kafka_pipeline.py
```

Kafka topics:
- `threat.raw.abuseipdb` / `threat.raw.otx` / `threat.raw.virustotal` / `threat.raw.nvd`
- `threat.normalized` — cleaned unified records
- `threat.alerts` — high/critical threats only
- `autoshield-live-feed` — ML team live feed

Kafka UI available at `http://localhost:8080`

---

## 🌿 Git Branching Strategy

```
main          ← stable, everything merged here
  ├── pipeline    ← ETL pipeline code
  ├── ml-models   ← Random Forest classifier
  └── firewall    ← Firewall rule applier & monitor
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| HTTP calls | requests |
| Data processing | pandas |
| Machine learning | scikit-learn (Random Forest) |
| Model persistence | joblib |
| File format | Parquet (pyarrow) |
| Database | SQLite (sqlalchemy) |
| Streaming | Apache Kafka (kafka-python) |
| Scheduling | schedule |
| Logging | logging + colorlog |
| Retry logic | tenacity |
| Config | python-dotenv |
| Containers | Docker + docker-compose |
| Version control | Git + GitHub |

---

## 📝 License

This project is part of the AutoShield Adaptive Threat Intelligence System.
Built for educational and research purposes.
