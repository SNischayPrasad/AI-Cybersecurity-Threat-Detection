"""
simulator.py - Virtual cyber-attack simulator.

We do not have access to a real corporate network, so this module creates
REALISTIC network connection logs ourselves. Each row is one network
connection, described with the same feature names used by the famous
KDD Cup 99 / NSL-KDD intrusion-detection datasets. That means:
  * our code also works on the real NSL-KDD dataset, and
  * every simulated attack leaves the same "fingerprint" a real one would.

Simulated traffic types
-----------------------
normal        Everyday office traffic (web, mail, DNS, file transfer, SSH).
dos           SYN-flood Denial of Service: thousands of half-open connections.
probe         Port scan: one host touching many different services.
brute_force   Password guessing against SSH / FTP / Telnet logins.
exfiltration  An insider uploading huge amounts of data late at night.
anomaly       A "zero-day" attack the model has NEVER seen during training
              (malformed fragmented packets). Only generated for live traffic,
              to prove the unsupervised detector can catch unknown threats.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# Services seen on a typical corporate network (names follow NSL-KDD).
NORMAL_SERVICES = ["http", "http", "http", "http", "smtp", "domain_u", "ftp_data", "ssh", "private"]
SCAN_SERVICES = [
    "http", "ftp", "telnet", "smtp", "finger", "auth", "private", "other", "ssh",
    "pop_3", "imap4", "sunrpc", "netbios_ns", "ldap", "domain", "time", "echo", "discard",
]
INTERNAL_SERVERS = ["10.0.0.10", "10.0.0.11", "10.0.0.20", "10.0.0.25", "10.0.0.53"]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _internal_ips(rng: np.random.Generator, n: int, pool: int = 120) -> np.ndarray:
    """Employee laptops: 10.0.1.x - 10.0.2.x"""
    hosts = [f"10.0.{1 + i // 250}.{1 + i % 250}" for i in range(pool)]
    return rng.choice(hosts, size=n)


def _external_ips(rng: np.random.Generator, count: int) -> list[str]:
    """Random public-looking attacker IPs."""
    return [f"{rng.integers(11, 223)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"
            for _ in range(count)]


def _timestamps_in_window(rng, day_start, n, start_hour, minutes) -> pd.Series:
    """n timestamps inside a burst window [start_hour, start_hour + minutes)."""
    offsets = rng.uniform(0, minutes * 60, size=n) + start_hour * 3600
    return day_start + pd.to_timedelta(np.sort(offsets), unit="s")


def _business_hours_timestamps(rng, day_start, n) -> pd.Series:
    """Normal users are busy 9am-6pm, quieter at night (diurnal pattern)."""
    hour_weights = np.array([1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 10, 10,
                             9, 10, 10, 10, 9, 8, 5, 4, 3, 2, 2, 1], dtype=float)
    hours = rng.choice(24, size=n, p=hour_weights / hour_weights.sum())
    seconds = hours * 3600 + rng.uniform(0, 3600, size=n)
    return day_start + pd.to_timedelta(seconds, unit="s")


def _base_frame(n: int) -> dict:
    """Default (all-zero) values for every feature column."""
    zeros = np.zeros(n)
    return {
        "duration": zeros.copy(), "protocol_type": ["tcp"] * n, "service": ["http"] * n,
        "flag": ["SF"] * n, "src_bytes": zeros.copy(), "dst_bytes": zeros.copy(),
        "wrong_fragment": zeros.copy(), "urgent": zeros.copy(), "num_failed_logins": zeros.copy(),
        "logged_in": zeros.copy(), "count": zeros.copy(), "srv_count": zeros.copy(),
        "serror_rate": zeros.copy(), "rerror_rate": zeros.copy(), "same_srv_rate": zeros.copy(),
        "diff_srv_rate": zeros.copy(), "dst_host_count": zeros.copy(), "dst_host_srv_count": zeros.copy(),
        "dst_host_same_srv_rate": zeros.copy(), "dst_host_serror_rate": zeros.copy(),
    }


# --------------------------------------------------------------------------
# Traffic generators - one per behaviour
# --------------------------------------------------------------------------
def simulate_normal(rng, n, day_start) -> pd.DataFrame:
    d = _base_frame(n)
    d["service"] = rng.choice(NORMAL_SERVICES, size=n)
    d["protocol_type"] = np.where(d["service"] == "domain_u", "udp", "tcp")
    # Real networks are noisy: a few rejected / reset connections are normal.
    d["flag"] = rng.choice(["SF", "SF", "SF", "SF", "SF", "SF", "SF", "SF", "REJ", "S0", "RSTO"], size=n)
    d["duration"] = np.round(rng.exponential(2.0, n) * (rng.random(n) < 0.3), 0)
    d["src_bytes"] = np.round(rng.lognormal(5.8, 1.1, n))
    d["dst_bytes"] = np.round(rng.lognormal(7.8, 1.6, n))
    d["logged_in"] = (rng.random(n) < 0.7).astype(float)
    d["num_failed_logins"] = (rng.random(n) < 0.01).astype(float)   # the odd typo
    d["count"] = rng.poisson(9, n) + 1
    d["srv_count"] = np.minimum(d["count"], rng.poisson(7, n) + 1)
    d["serror_rate"] = rng.beta(0.5, 25, n)
    d["rerror_rate"] = rng.beta(0.5, 25, n)
    d["same_srv_rate"] = rng.beta(8, 1.5, n)
    d["diff_srv_rate"] = rng.beta(1, 15, n)
    d["dst_host_count"] = rng.integers(1, 256, n)
    d["dst_host_srv_count"] = rng.integers(1, 256, n)
    d["dst_host_same_srv_rate"] = rng.beta(6, 2, n)
    d["dst_host_serror_rate"] = rng.beta(0.5, 25, n)
    df = pd.DataFrame(d)

    # --- Realistic "grey" traffic that looks a bit like attacks -------------
    # (without it the problem is unrealistically easy and every model scores 100%)
    # a) Ping / ICMP monitoring traffic, with the occasional fragmented packet.
    icmp = rng.random(n) < 0.03
    df.loc[icmp, "protocol_type"] = "icmp"
    df.loc[icmp, "service"] = rng.choice(["eco_i", "ecr_i"], size=icmp.sum())
    df.loc[icmp, ["src_bytes", "dst_bytes"]] = [64, 0]
    frag = rng.random(n) < 0.004
    df.loc[frag, "wrong_fragment"] = 1
    df.loc[rng.random(n) < 0.002, "urgent"] = 1
    # b) Nightly backups / large uploads (look like exfiltration by volume).
    backup = rng.random(n) < 0.006
    df.loc[backup, "src_bytes"] = np.round(rng.lognormal(13.5, 1.0, backup.sum()))
    df.loc[backup, "duration"] = np.round(rng.exponential(200, backup.sum()))
    # c) Busy moments on a popular server (high counts, some half-open conns).
    busy = rng.random(n) < 0.02
    df.loc[busy, "count"] = rng.integers(60, 250, busy.sum())
    df.loc[busy, "srv_count"] = df.loc[busy, "count"] - rng.integers(0, 30, busy.sum())
    df.loc[busy, "serror_rate"] = rng.beta(2, 6, busy.sum())
    # d) Users who mistype their password a few times.
    typo = rng.random(n) < 0.01
    df.loc[typo, "num_failed_logins"] = rng.integers(1, 3, typo.sum())
    df.loc[typo, "service"] = rng.choice(["ssh", "ftp"], size=typo.sum())

    df["timestamp"] = _business_hours_timestamps(rng, day_start, n)
    df["src_ip"] = _internal_ips(rng, n)
    df["dst_ip"] = rng.choice(INTERNAL_SERVERS, size=n)
    df["label"] = "normal"
    return df


def simulate_dos(rng, n, day_start, start_hour) -> pd.DataFrame:
    """SYN flood: half-open (S0) connections, zero payload, huge connection counts."""
    d = _base_frame(n)
    d["service"] = rng.choice(["http", "private"], size=n, p=[0.7, 0.3])
    d["flag"] = rng.choice(["S0", "S0", "S0", "S0", "S0", "S0", "S0", "S0", "SF", "REJ"], size=n)
    d["src_bytes"] = np.where(rng.random(n) < 0.9, 0, np.round(rng.lognormal(3, 1, n)))
    d["count"] = np.clip(rng.poisson(250, n), 20, 511)
    d["srv_count"] = np.clip(d["count"] - rng.integers(0, 15, n), 1, 511)
    d["serror_rate"] = rng.beta(20, 1.5, n)
    d["rerror_rate"] = rng.beta(0.5, 20, n)
    d["same_srv_rate"] = rng.beta(15, 1.5, n)
    d["diff_srv_rate"] = rng.beta(1, 25, n)
    d["dst_host_count"] = np.full(n, 255)
    d["dst_host_srv_count"] = rng.integers(200, 256, n)
    d["dst_host_same_srv_rate"] = rng.beta(15, 1.5, n)
    d["dst_host_serror_rate"] = rng.beta(20, 1.5, n)
    df = pd.DataFrame(d)
    # "Low-and-slow" variant (15%) that looks closer to normal - makes the task realistic.
    slow = rng.random(n) < 0.15
    df.loc[slow, "count"] = rng.poisson(35, slow.sum()) + 5
    df.loc[slow, "serror_rate"] = rng.beta(4, 3, slow.sum())
    df["timestamp"] = _timestamps_in_window(rng, day_start, n, start_hour, minutes=25)
    df["src_ip"] = rng.choice(_external_ips(rng, 25), size=n)     # a small botnet
    df["dst_ip"] = "10.0.0.10"                                     # the web server
    df["label"] = "dos"
    return df


def simulate_probe(rng, n, day_start, start_hour) -> pd.DataFrame:
    """Port scan: one attacker, many different services, mostly rejected."""
    d = _base_frame(n)
    d["service"] = rng.choice(SCAN_SERVICES, size=n)
    d["flag"] = rng.choice(["REJ", "REJ", "REJ", "S0", "RSTO", "SF"], size=n)
    d["src_bytes"] = np.where(rng.random(n) < 0.8, 0, rng.integers(1, 60, n))
    d["count"] = rng.poisson(60, n) + 1
    d["srv_count"] = rng.integers(1, 5, n)
    d["serror_rate"] = rng.beta(2, 5, n)
    d["rerror_rate"] = rng.beta(6, 2, n)
    d["same_srv_rate"] = rng.beta(1, 12, n)
    d["diff_srv_rate"] = rng.beta(6, 2, n)
    d["dst_host_count"] = rng.integers(150, 256, n)
    d["dst_host_srv_count"] = rng.integers(1, 15, n)
    d["dst_host_same_srv_rate"] = rng.beta(1, 15, n)
    d["dst_host_serror_rate"] = rng.beta(2, 5, n)
    df = pd.DataFrame(d)
    # Stealth scan variant (20%): slower, fewer rejections -> harder to spot.
    stealth = rng.random(n) < 0.20
    df.loc[stealth, "count"] = rng.poisson(12, stealth.sum()) + 1
    df.loc[stealth, "rerror_rate"] = rng.beta(2, 4, stealth.sum())
    df.loc[stealth, "dst_host_count"] = rng.integers(20, 200, stealth.sum())
    df["timestamp"] = _timestamps_in_window(rng, day_start, n, start_hour, minutes=20)
    df["src_ip"] = rng.choice(_external_ips(rng, 2), size=n)
    df["dst_ip"] = rng.choice(INTERNAL_SERVERS, size=n)
    df["label"] = "probe"
    return df


def simulate_brute_force(rng, n, day_start, start_hour) -> pd.DataFrame:
    """Credential stuffing / password guessing against login services."""
    d = _base_frame(n)
    d["service"] = rng.choice(["ssh", "ftp", "telnet"], size=n, p=[0.6, 0.3, 0.1])
    d["flag"] = rng.choice(["SF", "SF", "SF", "RSTO"], size=n)
    d["duration"] = rng.integers(0, 4, n)
    d["src_bytes"] = rng.integers(40, 400, n)
    d["dst_bytes"] = rng.integers(20, 300, n)
    d["num_failed_logins"] = np.clip(rng.poisson(2, n) + 1, 1, 5)
    d["logged_in"] = (rng.random(n) < 0.03).astype(float)          # rare success!
    d["count"] = rng.poisson(40, n) + 5
    d["srv_count"] = d["count"] - rng.integers(0, 3, n)
    d["serror_rate"] = rng.beta(0.5, 20, n)
    d["rerror_rate"] = rng.beta(1, 10, n)
    d["same_srv_rate"] = rng.beta(20, 1, n)
    d["diff_srv_rate"] = rng.beta(1, 30, n)
    d["dst_host_count"] = rng.integers(1, 20, n)
    d["dst_host_srv_count"] = rng.integers(100, 256, n)
    d["dst_host_same_srv_rate"] = rng.beta(20, 1, n)
    d["dst_host_serror_rate"] = rng.beta(0.5, 20, n)
    df = pd.DataFrame(d)
    # "Low and slow" password spraying (20%): 1 failure per connection, low rate.
    slow = rng.random(n) < 0.20
    df.loc[slow, "num_failed_logins"] = 1
    df.loc[slow, "count"] = rng.poisson(6, slow.sum()) + 1
    df.loc[slow, "srv_count"] = df.loc[slow, "count"]
    df.loc[slow, "dst_host_srv_count"] = rng.integers(5, 120, slow.sum())
    df["timestamp"] = _timestamps_in_window(rng, day_start, n, start_hour, minutes=50)
    df["src_ip"] = rng.choice(_external_ips(rng, 4), size=n)
    df["dst_ip"] = rng.choice(["10.0.0.20", "10.0.0.25"], size=n)
    df["label"] = "brute_force"
    return df


def simulate_exfiltration(rng, n, day_start, start_hour) -> pd.DataFrame:
    """Insider threat: long sessions uploading huge files after office hours."""
    d = _base_frame(n)
    d["service"] = rng.choice(["ftp_data", "http", "ssh"], size=n)
    d["duration"] = np.round(rng.exponential(400, n)) + 30
    d["src_bytes"] = np.round(rng.lognormal(14.5, 1.1, n))            # ~2 MB median per connection
    d["dst_bytes"] = np.round(rng.lognormal(5.0, 1.0, n))
    d["logged_in"] = np.ones(n)
    d["count"] = rng.poisson(3, n) + 1
    d["srv_count"] = d["count"]
    d["serror_rate"] = rng.beta(0.5, 30, n)
    d["rerror_rate"] = rng.beta(0.5, 30, n)
    d["same_srv_rate"] = rng.beta(10, 1, n)
    d["diff_srv_rate"] = rng.beta(1, 20, n)
    d["dst_host_count"] = rng.integers(1, 5, n)
    d["dst_host_srv_count"] = rng.integers(1, 5, n)
    d["dst_host_same_srv_rate"] = rng.beta(10, 1, n)
    df = pd.DataFrame(d)
    df["timestamp"] = _timestamps_in_window(rng, day_start, n, start_hour, minutes=55)
    insider = _internal_ips(rng, 1)[0]
    df["src_ip"] = insider
    df["dst_ip"] = rng.choice(_external_ips(rng, 2), size=n)          # attacker's cloud drop
    df["label"] = "exfiltration"
    return df


def simulate_zero_day(rng, n, day_start, start_hour) -> pd.DataFrame:
    """Unknown attack: malformed fragmented ICMP packets with urgent flags.
    Never present in training data -> only the anomaly detector can catch it."""
    d = _base_frame(n)
    d["protocol_type"] = ["icmp"] * n
    d["service"] = rng.choice(["eco_i", "ecr_i", "other"], size=n)
    d["flag"] = rng.choice(["SF", "OTH"], size=n)
    d["src_bytes"] = rng.integers(1400, 1500, n)
    d["wrong_fragment"] = rng.integers(1, 4, n)
    d["urgent"] = rng.integers(1, 3, n)
    d["count"] = rng.poisson(15, n) + 1
    d["srv_count"] = d["count"]
    d["same_srv_rate"] = rng.beta(5, 2, n)
    d["diff_srv_rate"] = rng.beta(2, 5, n)
    d["dst_host_count"] = rng.integers(1, 30, n)
    d["dst_host_srv_count"] = rng.integers(1, 30, n)
    d["dst_host_same_srv_rate"] = rng.beta(5, 2, n)
    df = pd.DataFrame(d)
    df["timestamp"] = _timestamps_in_window(rng, day_start, n, start_hour, minutes=15)
    df["src_ip"] = rng.choice(_external_ips(rng, 3), size=n)
    df["dst_ip"] = rng.choice(INTERNAL_SERVERS, size=n)
    df["label"] = "anomaly"
    return df


def _blend_benign_flows(rng, attack_df: pd.DataFrame, day_start, frac: float = 0.02) -> pd.DataFrame:
    """
    Real datasets (e.g. CICIDS2017) label traffic by "attacker IP + time window".
    So a few flows labelled as an attack are actually ordinary-looking requests
    the attacker also made (a DNS lookup, a normal page load). We replace `frac`
    of each attack's feature values with normal-looking ones, keeping the label.
    This label noise is what keeps any honest model below 100%.
    """
    attack_df = attack_df.copy()
    idx = np.flatnonzero(rng.random(len(attack_df)) < frac)
    if len(idx):
        benign = simulate_normal(rng, len(idx), day_start)
        feature_cols = [c for c in benign.columns if c not in ("timestamp", "src_ip", "dst_ip", "label")]
        numeric_cols = benign[feature_cols].select_dtypes("number").columns
        attack_df[numeric_cols] = attack_df[numeric_cols].astype(float)   # pandas 3 is strict about dtypes
        attack_df.loc[attack_df.index[idx], feature_cols] = benign[feature_cols].to_numpy()
    return attack_df


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def generate_traffic(
    n_normal: int = 20000,
    seed: int = 42,
    day: str = "2026-01-15",
    include_zero_day: bool = False,
) -> pd.DataFrame:
    """
    Simulate one full day of network traffic for a mid-sized company.

    Attack windows are randomised by `seed`, so the "training day" and the
    "live day" have attacks at DIFFERENT times - the model cannot cheat by
    memorising the clock.
    """
    rng = np.random.default_rng(seed)
    day_start = pd.Timestamp(day)

    # Attack volume is a fraction of normal traffic (attacks are the minority,
    # exactly like the real world -> class imbalance we must handle).
    parts = [
        simulate_normal(rng, n_normal, day_start),
        simulate_dos(rng, int(n_normal * 0.20), day_start, start_hour=int(rng.integers(0, 22))),
        simulate_probe(rng, int(n_normal * 0.08), day_start, start_hour=int(rng.integers(0, 23))),
        simulate_brute_force(rng, int(n_normal * 0.06), day_start, start_hour=int(rng.integers(0, 23))),
        # Exfiltration deliberately happens off-hours (22:00-23:00), as in real insider cases.
        simulate_exfiltration(rng, int(n_normal * 0.015), day_start, start_hour=int(rng.integers(22, 23))),
    ]
    if include_zero_day:
        parts.append(simulate_zero_day(rng, int(n_normal * 0.01), day_start,
                                       start_hour=int(rng.integers(0, 23))))

    parts = [parts[0]] + [_blend_benign_flows(rng, p, day_start) for p in parts[1:]]
    df = pd.concat(parts, ignore_index=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Round the rate columns to 2 decimals like the real dataset does.
    rate_cols = [c for c in df.columns if c.endswith("_rate")]
    df[rate_cols] = df[rate_cols].round(2)
    return df
