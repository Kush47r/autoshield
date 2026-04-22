"""
firewall/monitor.py
────────────────────
Monitors the alerts log and firewall apply log in real time.
Prints a live summary of blocked threats and recent alerts.

Usage:
    python firewall/monitor.py
    python firewall/monitor.py --watch          # continuous, refresh every 30s
    python firewall/monitor.py --summary-only   # one-shot summary then exit
"""

import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import get_logger

logger = get_logger("Monitor")

ALERTS_LOG  = Path(__file__).parent.parent / "logs" / "alerts.jsonl"
APPLY_LOG   = Path(__file__).parent.parent / "logs" / "firewall_apply.jsonl"
RULES_JSON  = Path(__file__).parent.parent / "data" / "firewall" / "firewall_rules.json"
BLOCK_IPS   = Path(__file__).parent.parent / "data" / "firewall" / "block_ips.txt"


def load_jsonl(path: Path, last_n: int = 100) -> list:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    records = []
    for line in lines[-last_n:]:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def summarise() -> dict:
    """Build a current-state summary from all log sources."""
    now = datetime.now(timezone.utc).isoformat()

    # ── Blocked IPs ───────────────────────────────────────────
    blocked_ips = 0
    if BLOCK_IPS.exists():
        lines = [l for l in BLOCK_IPS.read_text().splitlines() if l and not l.startswith("#")]
        blocked_ips = len(lines)

    # ── Firewall rules ────────────────────────────────────────
    total_rules   = 0
    blocked_domains = 0
    last_rule_gen   = "never"
    if RULES_JSON.exists():
        try:
            payload       = json.loads(RULES_JSON.read_text())
            total_rules   = payload.get("total_rules", 0)
            blocked_domains = payload.get("domains_blocked", 0)
            last_rule_gen   = payload.get("generated_at", "unknown")
        except Exception:
            pass

    # ── Recent alerts ─────────────────────────────────────────
    alerts = load_jsonl(ALERTS_LOG, last_n=20)
    sev_counts = Counter(a.get("severity", "unknown") for a in alerts)

    # ── Apply history ─────────────────────────────────────────
    applies = load_jsonl(APPLY_LOG)
    last_apply = applies[-1] if applies else {}

    return {
        "summary_at":       now,
        "blocked_ips":      blocked_ips,
        "blocked_domains":  blocked_domains,
        "total_rules":      total_rules,
        "rules_generated":  last_rule_gen,
        "recent_alerts":    len(alerts),
        "alert_severities": dict(sev_counts),
        "last_rule_apply":  last_apply.get("applied_at", "never"),
        "last_apply_status": last_apply.get("status", "n/a"),
    }


def print_summary(s: dict):
    print("\n" + "=" * 50)
    print("  AutoShield Firewall Monitor")
    print(f"  {s['summary_at']}")
    print("=" * 50)
    print(f"  Blocked IPs:      {s['blocked_ips']}")
    print(f"  Blocked Domains:  {s['blocked_domains']}")
    print(f"  Total Rules:      {s['total_rules']}")
    print(f"  Rules Generated:  {s['rules_generated']}")
    print(f"  Last Applied:     {s['last_rule_apply']}  [{s['last_apply_status']}]")
    print(f"  Recent Alerts:    {s['recent_alerts']}")
    if s["alert_severities"]:
        for sev, count in sorted(s["alert_severities"].items()):
            print(f"    {sev:12s}: {count}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoShield firewall monitor")
    parser.add_argument("--watch",        action="store_true", help="Continuously refresh")
    parser.add_argument("--interval",     type=int, default=30, help="Refresh interval in seconds")
    parser.add_argument("--summary-only", action="store_true", help="Print once and exit")
    args = parser.parse_args()

    if args.summary_only or not args.watch:
        print_summary(summarise())
    else:
        logger.info(f"Watching firewall state (refresh every {args.interval}s) — Ctrl+C to stop")
        try:
            while True:
                print_summary(summarise())
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nMonitor stopped.")
