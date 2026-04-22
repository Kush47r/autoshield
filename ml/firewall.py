"""
ml/firewall.py
──────────────
Reads the ML-scored threat data and generates firewall block rules for
all indicators predicted as high or critical.

Outputs (written to data/firewall/):
  block_ips.txt        — one IP per line (for ipset / denyhosts)
  block_domains.txt    — one domain per line (for DNS sink-hole or hosts)
  iptables_rules.sh    — ready-to-run iptables DROP commands
  hosts_block.txt      — /etc/hosts format for domain blocking
  firewall_rules.json  — full structured rules with metadata

Usage (standalone):
    python ml/firewall.py
    python ml/firewall.py --scored-data path/to/scored.parquet
    python ml/firewall.py --dry-run

Usage (imported):
    from ml.firewall import FirewallUpdater
    fw = FirewallUpdater()
    report = fw.update(scored_df)
"""

import sys
import json
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import get_logger

logger = get_logger("Firewall")

FIREWALL_DIR  = Path(__file__).parent.parent / "data" / "firewall"
SCORED_DATA   = Path(__file__).parent.parent / "data" / "processed" / "threats_latest_scored.parquet"
BLOCK_LEVELS  = {"high", "critical"}

_IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def _is_ip(value: str) -> bool:
    return bool(_IP_RE.match(str(value).strip()))


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(str(value).strip()))


class FirewallUpdater:
    def __init__(self, output_dir: Path = FIREWALL_DIR):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def update(self, scored_df: pd.DataFrame, dry_run: bool = False) -> dict:
        """
        Takes a scored DataFrame (output of ThreatPredictor.predict()),
        extracts indicators to block, and writes all rule files.
        """
        if "block_recommended" not in scored_df.columns:
            logger.error("DataFrame has no 'block_recommended' column. Run predictor first.")
            return {"status": "failed", "reason": "missing predictions"}

        # ── Filter to block-worthy records ─────────────────────
        block_df = scored_df[scored_df["block_recommended"] == True].copy()
        logger.info(f"Records flagged for blocking: {len(block_df)} / {len(scored_df)}")

        if block_df.empty:
            logger.info("No indicators to block — firewall rules unchanged.")
            return {"status": "no_action", "blocked": 0}

        # ── Separate IPs from domains ───────────────────────────
        block_df["_is_ip"]     = block_df["indicator_value"].apply(_is_ip)
        block_df["_is_domain"] = block_df["indicator_value"].apply(
            lambda v: _is_domain(v) and not _is_ip(v)
        )

        ip_rows     = block_df[block_df["_is_ip"]]
        domain_rows = block_df[block_df["_is_domain"]]

        ips     = ip_rows["indicator_value"].dropna().unique().tolist()
        domains = domain_rows["indicator_value"].dropna().unique().tolist()

        logger.info(f"  IPs to block:     {len(ips)}")
        logger.info(f"  Domains to block: {len(domains)}")

        ts = datetime.now(timezone.utc).isoformat()

        if not dry_run:
            self._write_block_ips(ips, ts)
            self._write_block_domains(domains, ts)
            self._write_iptables_script(ips, ts)
            self._write_hosts_file(domains, ts)
            self._write_json_rules(block_df, ips, domains, ts)

        report = {
            "status":          "success" if not dry_run else "dry_run",
            "generated_at":    ts,
            "total_blocked":   len(block_df),
            "ips_blocked":     len(ips),
            "domains_blocked": len(domains),
            "by_severity":     block_df["predicted_severity"].value_counts().to_dict(),
            "by_source":       block_df["source"].value_counts().to_dict(),
            "output_dir":      str(self.output_dir),
        }

        if not dry_run:
            report_path = self.output_dir / "last_update.json"
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Firewall update report → {report_path}")

        logger.info(f"Firewall rules generated — {len(ips)} IPs, {len(domains)} domains blocked.")
        return report

    # ── File writers ───────────────────────────────────────────

    def _write_block_ips(self, ips: list, ts: str):
        path = self.output_dir / "block_ips.txt"
        with open(path, "w") as f:
            f.write(f"# AutoShield block list — generated {ts}\n")
            f.write(f"# Total: {len(ips)} IPs\n\n")
            for ip in sorted(ips):
                f.write(ip + "\n")
        logger.info(f"IP block list → {path}")

    def _write_block_domains(self, domains: list, ts: str):
        path = self.output_dir / "block_domains.txt"
        with open(path, "w") as f:
            f.write(f"# AutoShield domain block list — generated {ts}\n")
            f.write(f"# Total: {len(domains)} domains\n\n")
            for d in sorted(domains):
                f.write(d + "\n")
        logger.info(f"Domain block list → {path}")

    def _write_iptables_script(self, ips: list, ts: str):
        path = self.output_dir / "iptables_rules.sh"
        with open(path, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"# AutoShield iptables rules — generated {ts}\n")
            f.write(f"# Blocks {len(ips)} malicious IPs\n")
            f.write("# Run as root: sudo bash iptables_rules.sh\n\n")
            f.write("set -e\n\n")
            f.write("# Create ipset if it doesn't exist\n")
            f.write("ipset create autoshield_blocklist hash:ip -exist\n")
            f.write("ipset flush autoshield_blocklist\n\n")
            f.write("# Add all IPs to the set\n")
            for ip in sorted(ips):
                f.write(f"ipset add autoshield_blocklist {ip}\n")
            f.write("\n# Apply DROP rule (idempotent)\n")
            f.write("iptables -I INPUT  -m set --match-set autoshield_blocklist src -j DROP 2>/dev/null || true\n")
            f.write("iptables -I OUTPUT -m set --match-set autoshield_blocklist dst -j DROP 2>/dev/null || true\n\n")
            f.write(f'echo "AutoShield: {len(ips)} IPs blocked."\n')
        logger.info(f"iptables script → {path}")

    def _write_hosts_file(self, domains: list, ts: str):
        path = self.output_dir / "hosts_block.txt"
        with open(path, "w") as f:
            f.write(f"# AutoShield hosts block — generated {ts}\n")
            f.write("# Append to /etc/hosts to sink-hole malicious domains\n\n")
            for d in sorted(domains):
                f.write(f"0.0.0.0  {d}\n")
                f.write(f"0.0.0.0  www.{d}\n")
        logger.info(f"hosts block file → {path}")

    def _write_json_rules(self, block_df: pd.DataFrame, ips: list, domains: list, ts: str):
        rules = []
        for _, row in block_df.iterrows():
            rules.append({
                "indicator_value":    row.get("indicator_value"),
                "indicator_type":     row.get("indicator_type"),
                "source":             row.get("source"),
                "threat_type":        row.get("threat_type"),
                "predicted_severity": row.get("predicted_severity"),
                "predicted_score":    row.get("predicted_score"),
                "confidence":         row.get("confidence"),
                "country":            row.get("country"),
                "description":        str(row.get("description", ""))[:200],
                "action":             "block",
                "generated_at":       ts,
            })

        payload = {
            "generated_at":   ts,
            "total_rules":    len(rules),
            "ips_blocked":    len(ips),
            "domains_blocked": len(domains),
            "rules":          rules,
        }

        path = self.output_dir / "firewall_rules.json"
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        logger.info(f"Structured rules JSON → {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate AutoShield firewall rules")
    parser.add_argument("--scored-data", type=Path, default=SCORED_DATA)
    parser.add_argument("--dry-run",     action="store_true", help="Print stats but don't write files")
    args = parser.parse_args()

    if not args.scored_data.exists():
        logger.error(f"Scored data not found: {args.scored_data}")
        logger.error("Run: python ml/predictor.py --out data/processed/threats_latest_scored.parquet")
        sys.exit(1)

    df     = pd.read_parquet(args.scored_data)
    fw     = FirewallUpdater()
    report = fw.update(df, dry_run=args.dry_run)
    print(json.dumps(report, indent=2))
