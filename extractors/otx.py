# extractors/otx.py

import requests
import pandas as pd
from extractors.base import BaseExtractor
from config.settings import settings


class OTXExtractor(BaseExtractor):
    """
    Fetches threat indicators from AlienVault OTX.
    OTX organizes threats into "pulses" — each pulse is a
    threat report containing multiple indicators (IPs, domains,
    file hashes, URLs etc.)
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    # We only care about these indicator types
    INDICATOR_TYPES = ["IPv4", "domain", "URL", "FileHash-MD5", "FileHash-SHA256"]

    def __init__(self):
        super().__init__()
        self.source_name = "AlienVault OTX"
        self.api_key = settings.OTX_API_KEY

    def _get_pulses(self, page: int = 1) -> dict:
        """
        Fetches one page of threat pulses.
        Underscore prefix means this is a private helper method —
        only used inside this class, not called from outside.
        """
        headers = {"X-OTX-API-KEY": self.api_key}

        response = requests.get(
            f"{self.BASE_URL}/pulses/subscribed",
            headers=headers,
            params={"limit": 10, "page": page},
            timeout=30
        )
        response.raise_for_status()
        return response.json()

    def extract(self) -> pd.DataFrame:

        if not self.api_key:
            self.logger.warning("OTX API key missing — skipping.")
            return pd.DataFrame()

        records = []
        page = 1
        max_pages = 3  # fetch 3 pages = 30 pulses max per run

        while page <= max_pages:
            self.logger.info(f"Fetching OTX pulse page {page}...")

            data = self._get_pulses(page)
            pulses = data.get("results", [])

            # If no pulses returned, stop looping
            if not pulses:
                break

            # Loop through each pulse (threat report)
            for pulse in pulses:
                pulse_name = pulse.get("name", "unknown")
                pulse_id   = pulse.get("id", "")
                tags       = ", ".join(pulse.get("tags", []))
                modified   = pulse.get("modified", "")

                # Each pulse contains multiple indicators
                for indicator in pulse.get("indicators", []):

                    # Skip types we don't care about
                    if indicator.get("type") not in self.INDICATOR_TYPES:
                        continue

                    records.append({
                        "indicator":      indicator.get("indicator", ""),
                        "indicator_type": indicator.get("type", ""),
                        "pulse_name":     pulse_name,
                        "pulse_id":       pulse_id,
                        "tags":           tags,
                        "pulse_modified": modified,
                        "description":    indicator.get("description", ""),
                    })

            # If no next page exists, stop
            if not data.get("next"):
                break

            page += 1

        if not records:
            self.logger.warning("OTX returned no indicators.")
            return pd.DataFrame()

        return pd.DataFrame(records)