"""
data_loader.py - Get data into a pandas DataFrame.

Two data sources are supported:

1. "synthetic" (default) - traffic produced by our own attack simulator
   (src/simulator.py). Works offline, no download, fully reproducible.

2. "nsl-kdd" - the real, public NSL-KDD benchmark dataset (an improved
   version of KDD Cup 99, used in hundreds of research papers). It is
   downloaded automatically the first time you use it.
"""

from __future__ import annotations

import urllib.request

import numpy as np
import pandas as pd

from src import config
from src.simulator import generate_traffic

# --------------------------------------------------------------------------
# Synthetic (simulated) data
# --------------------------------------------------------------------------
def generate_synthetic_datasets(n_normal: int = 20000) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Create Day-1 (training) and Day-2 (live, contains a zero-day) CSV files."""
    config.ensure_dirs()
    train = generate_traffic(n_normal=n_normal, seed=config.RANDOM_STATE,
                             day="2026-01-15", include_zero_day=False)
    live = generate_traffic(n_normal=n_normal // 2, seed=config.RANDOM_STATE + 1,
                            day="2026-01-16", include_zero_day=True)
    train.to_csv(config.TRAIN_FILE, index=False)
    live.to_csv(config.LIVE_FILE, index=False)
    return train, live


# --------------------------------------------------------------------------
# Real NSL-KDD data
# --------------------------------------------------------------------------
NSL_KDD_URLS = {
    "train": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "test": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
}

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack", "difficulty",
]

# NSL-KDD has ~40 specific attack names; we group them into families.
NSL_KDD_ATTACK_FAMILY = {
    # Denial of Service
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos", "smurf": "dos",
    "teardrop": "dos", "apache2": "dos", "udpstorm": "dos", "processtable": "dos",
    "mailbomb": "dos",
    # Probing / scanning
    "satan": "probe", "ipsweep": "probe", "nmap": "probe", "portsweep": "probe",
    "mscan": "probe", "saint": "probe",
    # Remote-to-local (password guessing, remote exploits)
    "guess_passwd": "brute_force", "ftp_write": "r2l", "imap": "r2l", "phf": "r2l",
    "multihop": "r2l", "warezmaster": "r2l", "warezclient": "r2l", "spy": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "snmpguess": "brute_force", "snmpgetattack": "r2l",
    "httptunnel": "r2l", "sendmail": "r2l", "named": "r2l",
    # User-to-root (privilege escalation)
    "buffer_overflow": "u2r", "loadmodule": "u2r", "rootkit": "u2r", "perl": "u2r",
    "sqlattack": "u2r", "xterm": "u2r", "ps": "u2r",
    "normal": "normal",
}


def _download(url: str, dest) -> None:
    if dest.exists():
        return
    print(f"[download] {url} -> {dest}")
    urllib.request.urlretrieve(url, dest)


def _add_fake_context(df: pd.DataFrame, day: str, seed: int) -> pd.DataFrame:
    """NSL-KDD has no timestamps/IPs; add synthetic ones so alerts look like SOC alerts."""
    rng = np.random.default_rng(seed)
    start = pd.Timestamp(day)
    df["timestamp"] = start + pd.to_timedelta(np.sort(rng.uniform(0, 86400, len(df))), unit="s")
    df["src_ip"] = [f"10.0.{rng.integers(1, 5)}.{rng.integers(1, 254)}" for _ in range(len(df))]
    df["dst_ip"] = [f"10.0.0.{rng.integers(2, 60)}" for _ in range(len(df))]
    return df


def load_nsl_kdd() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Download (once) and load NSL-KDD. KDDTest+ contains attack types that are
    NOT in KDDTrain+ - a real-world 'zero-day' test for our anomaly detector."""
    config.ensure_dirs()
    frames = {}
    for split, url in NSL_KDD_URLS.items():
        path = config.DATA_RAW_DIR / f"nsl_kdd_{split}.txt"
        _download(url, path)
        df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
        df["label"] = df["attack"].map(NSL_KDD_ATTACK_FAMILY).fillna("anomaly")
        df = df.drop(columns=["attack", "difficulty"])
        frames[split] = _add_fake_context(df, "2026-01-15" if split == "train" else "2026-01-16",
                                          seed=config.RANDOM_STATE)
    # Attack families never seen in training are re-labelled "anomaly" in the test set.
    known = set(frames["train"]["label"].unique())
    test = frames["test"]
    test.loc[~test["label"].isin(known), "label"] = "anomaly"
    return frames["train"], test


# --------------------------------------------------------------------------
# Single entry point used by main.py
# --------------------------------------------------------------------------
def load_datasets(source: str = "synthetic", regenerate: bool = False) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (training_df, live_df)."""
    if source == "nsl-kdd":
        return load_nsl_kdd()

    if regenerate or not (config.TRAIN_FILE.exists() and config.LIVE_FILE.exists()):
        return generate_synthetic_datasets()

    train = pd.read_csv(config.TRAIN_FILE, parse_dates=["timestamp"])
    live = pd.read_csv(config.LIVE_FILE, parse_dates=["timestamp"])
    return train, live
