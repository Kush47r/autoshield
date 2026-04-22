RAW_ABUSEIPDB  = "threat.raw.abuseipdb"
RAW_OTX        = "threat.raw.otx"
RAW_VIRUSTOTAL = "threat.raw.virustotal"
RAW_NVD        = "threat.raw.nvd"

NORMALIZED = "threat.normalized"
ALERTS     = "threat.alerts"

SOURCE_TO_TOPIC = {
    "abuseipdb":  RAW_ABUSEIPDB,
    "otx":        RAW_OTX,
    "virustotal": RAW_VIRUSTOTAL,
    "nvd":        RAW_NVD,
}

ALL_RAW_TOPICS = list(SOURCE_TO_TOPIC.values())
