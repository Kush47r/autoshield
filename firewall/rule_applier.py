"""
firewall/rule_applier.py
─────────────────────────
Reads firewall_rules.json produced by the ML pipeline and applies
the block rules to the host system.

Supports two backends:
  iptables  — Linux kernel firewall (requires root + ipset)
  hosts     — /etc/hosts domain sink-hole (works cross-platform)
  dry_run   — prints what WOULD be applied without touching the system

Usage:
    python firewall/rule_applier.py --backend iptables
    python firewall/rule_applier.py --backend hosts
    python firewall/rule_applier.py --dry-run
"""

import sys
import json
import subprocess
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import get_logger

logger = get_logger("RuleApplier")

RULES_JSON    = Path(__file__).parent.parent / "data" / "firewall" / "firewall_rules.json"
BLOCK_IPS_TXT = Path(__file__).parent.parent / "data" / "firewall" / "block_ips.txt"
HOSTS_BLOCK   = Path(__file__).parent.parent / "data" / "firewall" / "hosts_block.txt"
APPLY_LOG     = Path(__file__).parent.parent / "logs" / "firewall_apply.jsonl"

AUTOSHIELD_MARKER_START = "# --- AutoShield block start ---"
AUTOSHIELD_MARKER_END   = "# --- AutoShield block end ---"


class RuleApplier:
    def __init__(self, backend: str = "dry_run"):
        """
        backend: 'iptables' | 'hosts' | 'dry_run'
        """
        if backend not in ("iptables", "hosts", "dry_run"):
            raise ValueError(f"Unknown backend: {backend}")
        self.backend = backend

    def apply(self, rules_path: Path = RULES_JSON) -> dict:
        if not rules_path.exists():
            logger.error(f"Rules file not found: {rules_path}")
            logger.error("Run the ML pipeline first: python pipeline.py")
            return {"status": "failed", "reason": "rules file missing"}

        with open(rules_path) as f:
            payload = json.load(f)

        rules    = payload.get("rules", [])
        ips      = [r["indicator_value"] for r in rules if _is_ip(r["indicator_value"])]
        domains  = [r["indicator_value"] for r in rules if _is_domain(r["indicator_value"])]

        logger.info(f"Applying rules via [{self.backend}] — {len(ips)} IPs, {len(domains)} domains")

        if self.backend == "iptables":
            result = self._apply_iptables(ips)
        elif self.backend == "hosts":
            result = self._apply_hosts(domains)
        else:
            result = self._dry_run(ips, domains)

        result["applied_at"] = datetime.now(timezone.utc).isoformat()
        result["backend"]    = self.backend
        result["ips"]        = len(ips)
        result["domains"]    = len(domains)

        self._log_apply(result)
        return result

    # ── Backends ──────────────────────────────────────────────

    def _apply_iptables(self, ips: list) -> dict:
        if not ips:
            logger.info("No IPs to block via iptables.")
            return {"status": "no_action"}

        try:
            _run(["ipset", "create", "autoshield_blocklist", "hash:ip", "-exist"])
            _run(["ipset", "flush",  "autoshield_blocklist"])

            for ip in ips:
                _run(["ipset", "add", "autoshield_blocklist", ip])

            _run(["iptables", "-I", "INPUT",  "-m", "set", "--match-set",
                  "autoshield_blocklist", "src", "-j", "DROP"])
            _run(["iptables", "-I", "OUTPUT", "-m", "set", "--match-set",
                  "autoshield_blocklist", "dst", "-j", "DROP"])

            logger.info(f"iptables: {len(ips)} IPs added to autoshield_blocklist and dropped.")
            return {"status": "success", "ips_blocked": len(ips)}

        except Exception as e:
            logger.error(f"iptables apply failed: {e}")
            logger.error("Are you running as root? Is ipset installed?")
            return {"status": "failed", "error": str(e)}

    def _apply_hosts(self, domains: list) -> dict:
        if not domains:
            logger.info("No domains to block via hosts file.")
            return {"status": "no_action"}

        try:
            hosts_path = Path("/etc/hosts")
            if not hosts_path.exists():
                hosts_path = Path("C:/Windows/System32/drivers/etc/hosts")

            content = hosts_path.read_text(encoding="utf-8") if hosts_path.exists() else ""

            # Remove previous AutoShield block
            lines = content.splitlines()
            new_lines, inside = [], False
            for line in lines:
                if line.strip() == AUTOSHIELD_MARKER_START:
                    inside = True
                elif line.strip() == AUTOSHIELD_MARKER_END:
                    inside = False
                elif not inside:
                    new_lines.append(line)

            # Append fresh block
            new_lines += [
                "",
                AUTOSHIELD_MARKER_START,
                f"# Generated {datetime.now(timezone.utc).isoformat()}",
            ]
            for d in sorted(domains):
                new_lines.append(f"0.0.0.0  {d}")
                new_lines.append(f"0.0.0.0  www.{d}")
            new_lines.append(AUTOSHIELD_MARKER_END)

            hosts_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            logger.info(f"hosts file updated — {len(domains)} domains sink-holed at {hosts_path}")
            return {"status": "success", "domains_blocked": len(domains)}

        except PermissionError:
            logger.error("Permission denied writing hosts file. Run as root/Administrator.")
            return {"status": "failed", "error": "permission denied"}
        except Exception as e:
            logger.error(f"hosts apply failed: {e}")
            return {"status": "failed", "error": str(e)}

    def _dry_run(self, ips: list, domains: list) -> dict:
        logger.info("DRY RUN — no changes applied.")
        logger.info(f"  Would block {len(ips)} IPs via iptables/ipset")
        logger.info(f"  Would sink-hole {len(domains)} domains via hosts file")
        for ip in ips[:10]:
            logger.info(f"    DROP: {ip}")
        if len(ips) > 10:
            logger.info(f"    ... and {len(ips) - 10} more")
        for d in domains[:10]:
            logger.info(f"    SINK: {d}")
        return {"status": "dry_run", "ips": len(ips), "domains": len(domains)}

    def _log_apply(self, result: dict):
        APPLY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(APPLY_LOG, "a") as f:
            f.write(json.dumps(result) + "\n")


def _is_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(value).strip()))


def _is_domain(value: str) -> bool:
    import re
    return bool(re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", str(value).strip())) and not _is_ip(value)


def _run(cmd: list):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply AutoShield firewall rules")
    parser.add_argument("--rules",   type=Path,  default=RULES_JSON)
    parser.add_argument("--backend", type=str,   default="dry_run",
                        choices=["iptables", "hosts", "dry_run"])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    backend = "dry_run" if args.dry_run else args.backend
    applier = RuleApplier(backend=backend)
    report  = applier.apply(rules_path=args.rules)
    print(json.dumps(report, indent=2))
