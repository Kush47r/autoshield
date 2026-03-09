# extractors/virustotal.py

import time
import requests
import pandas as pd
from extractors.base import BaseExtractor
from config.settings import settings


class VirusTotalExtractor(BaseExtractor):
    """
    Fetches malicious IPs and domains from VirusTotal.
    Free tier: 500 requests/day, 4 requests/minute.
    We use direct lookups instead of search (free tier limitation).
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        super().__init__()
        self.source_name = "VirusTotal"
        self.api_key = settings.VIRUSTOTAL_API_KEY

    @property
    def _headers(self):
        return {"x-apikey": self.api_key}

    def _lookup(self, indicator: str, ioc_type: str) -> list:
        """
        Direct lookup of a specific IP or domain.
        Works on free tier unlike advanced search queries.
        ioc_type: 'ip_addresses' or 'domains'
        """
        endpoint = f"{self.BASE_URL}/{ioc_type}/{indicator}"

        response = requests.get(
            endpoint,
            headers=self._headers,
            timeout=30
        )

        if response.status_code == 429:
            self.logger.warning("Rate limit hit — waiting 60s...")
            time.sleep(60)
            response = requests.get(
                endpoint,
                headers=self._headers,
                timeout=30
            )

        # 404 means VT has no data on this indicator — skip it
        if response.status_code == 404:
            self.logger.warning(f"No VT data for {indicator} — skipping")
            return []

        response.raise_for_status()

        # Direct lookup returns a single object not a list
        # so we wrap it in a list to keep _parse_items() happy
        data = response.json().get("data", {})
        return [data] if data else []

    def _parse_items(self, items: list, indicator_type: str) -> list:
        """
        Pulls out the fields we care about from raw VT results.
        """
        records = []

        for item in items:
            attrs = item.get("attributes", {})

            # last_analysis_stats shows how many engines
            # flagged this item as malicious, suspicious etc.
            stats = attrs.get("last_analysis_stats", {})

            records.append({
                "indicator":          item.get("id", ""),
                "indicator_type":     indicator_type,
                "malicious_count":    stats.get("malicious", 0),
                "suspicious_count":   stats.get("suspicious", 0),
                "harmless_count":     stats.get("harmless", 0),
                "undetected_count":   stats.get("undetected", 0),
                "reputation":         attrs.get("reputation", 0),
                "country":            attrs.get("country", ""),
                "as_owner":           attrs.get("as_owner", ""),
                "tags":               ", ".join(attrs.get("tags", [])),
                "last_analysis_date": attrs.get("last_analysis_date", ""),
            })

        return records

    def extract(self) -> pd.DataFrame:

        if not self.api_key:
            self.logger.warning("VirusTotal API key missing — skipping.")
            return pd.DataFrame()

        all_records = []

        # --- Lookup known malicious IPs directly ---
        known_malicious_ips = [
            "185.220.101.1",
            "45.142.212.100",
            "194.165.16.11",
            "91.92.109.196",
            "193.32.162.157",
        ]

        self.logger.info("Looking up malicious IPs on VirusTotal...")
        for ip in known_malicious_ips:
            items = self._lookup(ip, "ip_addresses")
            all_records.extend(self._parse_items(items, "ip_address"))
            self.logger.info(f"Looked up {ip} — waiting 16s...")
            time.sleep(16)  # stay within 4 requests/minute

        # --- Lookup known malicious domains directly ---
        known_malicious_domains = [
            "malware-traffic-analysis.net",
            "iplogger.org",
            "grabify.link",
            "freegeoip.app",
            "canarytokens.org",
        ]

        self.logger.info("Looking up malicious domains on VirusTotal...")
        for domain in known_malicious_domains:
            items = self._lookup(domain, "domains")
            all_records.extend(self._parse_items(items, "domain"))
            self.logger.info(f"Looked up {domain} — waiting 16s...")
            time.sleep(16)

        if not all_records:
            self.logger.warning("VirusTotal returned no records.")
            return pd.DataFrame()

        return pd.DataFrame(all_records)