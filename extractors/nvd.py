# extractors/nvd.py

import requests
import pandas as pd
from datetime import datetime, timedelta
from extractors.base import BaseExtractor
from config.settings import settings


class NVDExtractor(BaseExtractor):
    """
    Fetches recently modified CVEs from NIST NVD.
    Uses lastModStartDate/lastModEndDate — recommended for daily pipelines.
    No API key required. Free and open.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        super().__init__()
        self.source_name = "NVD/CVE"

    def extract(self) -> pd.DataFrame:

        # Last 7 days of modified CVEs
        end_dt   = datetime.utcnow()
        start_dt = end_dt - timedelta(days=7)

        # NVD requires ISO 8601 format with milliseconds
        start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_date   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        self.logger.info(f"Fetching CVEs modified from {start_date} to {end_date}")

        # Use lastMod dates — recommended for pipelines by NVD docs
        # Build URL manually to prevent colon encoding
        url = (
            f"{self.BASE_URL}"
            f"?lastModStartDate={start_date}"
            f"&lastModEndDate={end_date}"
            f"&resultsPerPage=50"
        )

        self.logger.info(f"Calling: {url}")

        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        response = requests.get(url, headers=headers, timeout=60)

        # Print the error message from NVD header if something goes wrong
        if not response.ok:
            error_msg = response.headers.get("message", "no message in header")
            self.logger.error(f"NVD error header message: {error_msg}")
            self.logger.error(f"Response status: {response.status_code}")
            self.logger.error(f"Response body: {response.text[:300]}")
            response.raise_for_status()

        data            = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total           = data.get("totalResults", 0)

        self.logger.info(f"NVD returned {total} total CVEs — parsing top 50...")

        if not vulnerabilities:
            self.logger.warning("NVD returned no CVEs for this date range.")
            return pd.DataFrame()

        records = []

        for item in vulnerabilities:
            cve = item.get("cve", {})

            cve_id    = cve.get("id", "")
            published = cve.get("published", "")
            modified  = cve.get("lastModified", "")
            status    = cve.get("vulnStatus", "")

            # English description only
            descriptions = cve.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # CVSS Score — try v3.1 first, then v3.0, then v2.0
            cvss_score    = None
            cvss_severity = None
            metrics       = cve.get("metrics", {})

            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    m             = metrics[version][0]
                    cvss_data     = m.get("cvssData", {})
                    cvss_score    = cvss_data.get("baseScore")
                    cvss_severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
                    break

            # CWE weakness type
            weaknesses = cve.get("weaknesses", [])
            cwes       = []
            for w in weaknesses:
                for d in w.get("description", []):
                    cwes.append(d.get("value", ""))
            cwe_str = ", ".join(cwes)

            # Affected products
            configs      = cve.get("configurations", [])
            affected     = []
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable"):
                            affected.append(cpe.get("criteria", ""))
            affected_str = " | ".join(affected[:3])

            records.append({
                "cve_id":            cve_id,
                "published":         published,
                "last_modified":     modified,
                "status":            status,
                "description":       description[:300],
                "cvss_score":        cvss_score,
                "cvss_severity":     cvss_severity,
                "cwe":               cwe_str,
                "affected_products": affected_str,
            })

        return pd.DataFrame(records)