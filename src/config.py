"""
config.py - Central configuration for the whole project.

Every path, constant and "magic number" lives here so that the rest of the
code never hard-codes values. Change something once here and every module
picks it up.
"""

from pathlib import Path

# --------------------------------------------------------------------------
# Paths (all relative to the project root, so the repo works on any machine)
# --------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent

DATA_RAW_DIR = ROOT_DIR / "data" / "raw"
DATA_PROCESSED_DIR = ROOT_DIR / "data" / "processed"
MODELS_DIR = ROOT_DIR / "models"
OUTPUTS_DIR = ROOT_DIR / "outputs"
IMAGES_DIR = ROOT_DIR / "images"

TRAIN_FILE = DATA_RAW_DIR / "train_traffic.csv"   # "Day 1" - labelled history
LIVE_FILE = DATA_RAW_DIR / "live_traffic.csv"     # "Day 2" - traffic to monitor
MODEL_FILE = MODELS_DIR / "threat_detector.joblib"
METRICS_FILE = OUTPUTS_DIR / "metrics.json"

# --------------------------------------------------------------------------
# Reproducibility
# --------------------------------------------------------------------------
RANDOM_STATE = 42
TEST_SIZE = 0.25

# --------------------------------------------------------------------------
# Column definitions
# --------------------------------------------------------------------------
LABEL_COL = "label"              # attack category, e.g. "normal", "dos"
NORMAL_LABEL = "normal"

# Text columns that must be one-hot encoded before a model can use them.
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# Context columns a SOC analyst needs to see, but the model must NOT learn
# from (an IP address is an identifier, not a behaviour).
META_COLS = ["timestamp", "src_ip", "dst_ip"]

# --------------------------------------------------------------------------
# Detection settings
# --------------------------------------------------------------------------
# Classifier must be at least this confident before we call something a
# known attack.
CLASSIFIER_CONFIDENCE = 0.50

# Isolation Forest threshold = this percentile of anomaly scores seen on
# NORMAL training traffic. 99 => roughly 1% false-alarm budget.
ANOMALY_PERCENTILE = 99.0

# Base severity for each threat type (SOC triage priority).
SEVERITY_BY_TYPE = {
    "exfiltration": "CRITICAL",
    "dos": "HIGH",
    "brute_force": "HIGH",
    "probe": "MEDIUM",
    "anomaly": "MEDIUM",
    # Extra categories that appear in the real NSL-KDD dataset
    "r2l": "HIGH",
    "u2r": "CRITICAL",
}
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# MITRE ATT&CK mapping - the industry-standard vocabulary SOC teams use.
MITRE_BY_TYPE = {
    "dos": "T1498 - Network Denial of Service",
    "probe": "T1046 - Network Service Discovery",
    "brute_force": "T1110 - Brute Force",
    "exfiltration": "T1048 - Exfiltration Over Alternative Protocol",
    "r2l": "T1078 - Valid Accounts / Remote Access",
    "u2r": "T1068 - Exploitation for Privilege Escalation",
    "anomaly": "Unmapped - possible zero-day, needs analyst review",
}

RECOMMENDED_ACTION = {
    "dos": "Rate-limit / block source IPs at the firewall; enable SYN cookies.",
    "probe": "Block scanning IP; review exposed ports and services.",
    "brute_force": "Lock targeted account; enforce MFA; block source IP.",
    "exfiltration": "Isolate host immediately; capture traffic; start IR process.",
    "r2l": "Reset credentials; audit remote access logs.",
    "u2r": "Isolate host; check for privilege escalation artefacts.",
    "anomaly": "Escalate to Tier-2 analyst for manual investigation.",
}


def ensure_dirs() -> None:
    """Create every output folder if it does not exist yet."""
    for folder in (DATA_RAW_DIR, DATA_PROCESSED_DIR, MODELS_DIR, OUTPUTS_DIR, IMAGES_DIR):
        folder.mkdir(parents=True, exist_ok=True)
