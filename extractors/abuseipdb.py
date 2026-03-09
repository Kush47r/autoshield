# extractors/abuseipdb.py

import requests
import pandas as pd
from extractors.base import BaseExtractor
from config.settings import settings


class AbuseIPDBExtractor(BaseExtractor):
    """
    Fetches the most reported malicious IPs from AbuseIPDB.
    Inherits from BaseExtractor so it gets run() and logger for free.
    """

    # The URL we are calling
    BASE_URL = "https://api.abuseipdb.com/api/v2/blacklist"

    def __init__(self):
        # Call parent __init__ first — sets up self.logger
        super().__init__()
        # Override the source name from "unknown" to this
        self.source_name = "AbuseIPDB"
        # Read API key from settings (which reads from .env)
        self.api_key = settings.ABUSEIPDB_API_KEY

    def extract(self) -> pd.DataFrame:

        # If no API key found, skip gracefully instead of crashing
        if not self.api_key:
            self.logger.warning("AbuseIPDB API key missing — skipping.")
            return pd.DataFrame()

        # --- Build the request ---
        # Headers tell the API who we are
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

        # Parameters filter what data we get back
        params = {
            "confidenceMinimum": 90,  # only IPs reported with 90%+ confidence
            "limit": 100              # get 100 IPs (free tier limit)
        }

        self.logger.info(f"Calling AbuseIPDB API...")

        # --- Make the API call ---
        # requests.get() sends an HTTP GET request to the URL
        # timeout=30 means give up if no response in 30 seconds
        response = requests.get(
            self.BASE_URL,
            headers=headers,
            params=params,
            timeout=30
        )

        # raise_for_status() crashes if response is 4xx or 5xx error
        # e.g. 401 = wrong API key, 429 = rate limited
        response.raise_for_status()

        # --- Parse the response ---
        # The API returns JSON — convert it to a Python dict
        raw = response.json()

        # The actual list of IPs is inside the "data" key
        data = raw.get("data", [])

        if not data:
            self.logger.warning("AbuseIPDB returned empty data.")
            return pd.DataFrame()

        # --- Convert to DataFrame ---
        # pd.DataFrame(list_of_dicts) turns the list into a table
        df = pd.DataFrame(data)

        self.logger.info(f"Raw columns received: {list(df.columns)}")

        # Rename columns to cleaner names
        df = df.rename(columns={
            "ipAddress":            "ip_address",
            "abuseConfidenceScore": "confidence_score",
            "countryCode":          "country_code",
            "usageType":            "usage_type",
            "isp":                  "isp",
            "domain":               "domain",
            "totalReports":         "total_reports",
            "lastReportedAt":       "last_reported_at",
            "numDistinctUsers":     "distinct_reporters",
        })

        return df