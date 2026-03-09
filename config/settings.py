import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:

    ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY        = os.getenv("OTX_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    NVD_API_KEY        = os.getenv("NVD_API_KEY", "")

    STORAGE_TYPE = os.getenv("STORAGE_TYPE", "sqlite")

    BASE_DIR      = Path(__file__).parent.parent
    DATA_DIR      = BASE_DIR / "data"
    RAW_DIR       = DATA_DIR / "raw"
    PROCESSED_DIR = DATA_DIR / "processed"
    LOG_DIR       = BASE_DIR / "logs"

    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    def validate(self):
        missing = []
        if not self.ABUSEIPDB_API_KEY:  missing.append("ABUSEIPDB_API_KEY")
        if not self.OTX_API_KEY:        missing.append("OTX_API_KEY")
        if not self.VIRUSTOTAL_API_KEY: missing.append("VIRUSTOTAL_API_KEY")
        return missing

settings = Settings()