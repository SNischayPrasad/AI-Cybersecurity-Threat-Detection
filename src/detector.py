"""
detector.py - Threat detection logic and SOC alert generation.

This is the "brain" that runs in production. For every connection:

  1. Random Forest predicts the attack type + a confidence score.
  2. Isolation Forest gives an anomaly score.
  3. Decision rules combine both into a verdict:
       KNOWN_ATTACK  - classifier is confident it is a known attack type
       ANOMALY       - classifier says normal, but behaviour is very unusual
                       (possible zero-day)
       BENIGN        - nothing suspicious
  4. Suspicious connections become ALERTS with severity, MITRE ATT&CK
     technique and a recommended action.
  5. Alerts from the same attacker are grouped into INCIDENTS, so an analyst
     sees "1 DoS incident from 25 IPs" instead of 4,000 separate alerts.
"""

from __future__ import annotations

import joblib
import numpy as np
import pandas as pd

from src import config
from src.models import anomaly_scores
from src.preprocessing import split_features_labels


# --------------------------------------------------------------------------
# Model bundle (classifier + anomaly detector + threshold) persistence
# --------------------------------------------------------------------------
def save_bundle(classifier, anomaly_detector, threshold: float, path=config.MODEL_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"classifier": classifier, "anomaly_detector": anomaly_detector,
                 "anomaly_threshold": threshold}, path)
    print(f"[save] model bundle -> {path.relative_to(config.ROOT_DIR)}")


def load_bundle(path=config.MODEL_FILE) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"No trained model at {path}. Run:  python main.py train")
    return joblib.load(path)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def _lower_severity(level: str) -> str:
    idx = config.SEVERITY_ORDER.index(level)
    return config.SEVERITY_ORDER[max(idx - 1, 0)]


def detect(df: pd.DataFrame, bundle: dict) -> pd.DataFrame:
    """Score every row of a CLEANED dataframe and return it with verdict columns."""
    X, _ = split_features_labels(df)
    clf, iso, threshold = bundle["classifier"], bundle["anomaly_detector"], bundle["anomaly_threshold"]

    proba = clf.predict_proba(X)
    classes = clf.classes_
    pred_idx = proba.argmax(axis=1)

    out = df.copy()
    out["predicted_type"] = classes[pred_idx]
    out["confidence"] = proba[np.arange(len(X)), pred_idx].round(4)
    out["anomaly_score"] = anomaly_scores(iso, X).round(4)
    out["is_anomalous"] = out["anomaly_score"] >= threshold

    known_attack = (out["predicted_type"] != config.NORMAL_LABEL) & (out["confidence"] >= config.CLASSIFIER_CONFIDENCE)
    unknown_anomaly = ~known_attack & out["is_anomalous"]

    out["verdict"] = np.select([known_attack, unknown_anomaly], ["KNOWN_ATTACK", "ANOMALY"], default="BENIGN")
    out["threat_type"] = np.where(known_attack, out["predicted_type"],
                                  np.where(unknown_anomaly, "anomaly", config.NORMAL_LABEL))

    # Severity: base level by threat type ...
    base = out["threat_type"].map(config.SEVERITY_BY_TYPE).fillna("MEDIUM")
    # ... lowered one step when the classifier is unsure ...
    unsure = known_attack & (out["confidence"] < 0.70)
    base = base.where(~unsure, base.map(_lower_severity))
    # ... raised to HIGH when an unknown anomaly is extremely unusual.
    extreme = unknown_anomaly & (out["anomaly_score"] >= threshold * 1.15)
    base = base.where(~extreme, "HIGH")
    out["severity"] = base.where(out["verdict"] != "BENIGN", "NONE")
    return out


# --------------------------------------------------------------------------
# Alerts & incidents
# --------------------------------------------------------------------------
def _reason(row) -> str:
    if row["verdict"] == "KNOWN_ATTACK":
        return f"Classifier matched '{row['threat_type']}' pattern ({row['confidence']:.0%} confidence)"
    return f"Behaviour deviates from normal baseline (anomaly score {row['anomaly_score']:.3f})"


def generate_alerts(results: pd.DataFrame, start_id: int = 1) -> pd.DataFrame:
    """Turn suspicious rows into SOC-style alert records."""
    alerts = results[results["verdict"] != "BENIGN"].copy()
    alerts = alerts.sort_values("timestamp").reset_index(drop=True)
    alerts.insert(0, "alert_id", [f"ALERT-{i:06d}" for i in range(start_id, start_id + len(alerts))])
    alerts["mitre_attack"] = alerts["threat_type"].map(config.MITRE_BY_TYPE)
    alerts["recommended_action"] = alerts["threat_type"].map(config.RECOMMENDED_ACTION)
    alerts["reason"] = alerts.apply(_reason, axis=1)
    keep = ["alert_id", "timestamp", "src_ip", "dst_ip", "protocol_type", "service", "flag",
            "src_bytes", "dst_bytes", "verdict", "threat_type", "severity", "confidence",
            "anomaly_score", "mitre_attack", "reason", "recommended_action"]
    if config.LABEL_COL in alerts.columns:
        keep.append(config.LABEL_COL)            # ground truth, only for scoring the simulation
    return alerts[keep]


def build_incidents(alerts: pd.DataFrame) -> pd.DataFrame:
    """Group alerts by (threat type, source IP) -> fewer, richer incidents."""
    if alerts.empty:
        return pd.DataFrame()
    sev_rank = {s: i for i, s in enumerate(config.SEVERITY_ORDER)}
    grouped = alerts.assign(sev_rank=alerts["severity"].map(sev_rank)).groupby(["threat_type", "src_ip"])
    incidents = grouped.agg(
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
        alert_count=("alert_id", "count"), targets=("dst_ip", "nunique"),
        total_bytes_out=("src_bytes", "sum"), max_sev_rank=("sev_rank", "max"),
    ).reset_index()
    incidents["severity"] = incidents["max_sev_rank"].map(dict(enumerate(config.SEVERITY_ORDER)))
    incidents["mitre_attack"] = incidents["threat_type"].map(config.MITRE_BY_TYPE)
    incidents = incidents.drop(columns="max_sev_rank").sort_values(
        ["severity", "alert_count"], key=lambda s: s.map(sev_rank) if s.name == "severity" else s,
        ascending=False).reset_index(drop=True)
    incidents.insert(0, "incident_id", [f"INC-{i:04d}" for i in range(1, len(incidents) + 1)])
    return incidents


def detection_scorecard(results: pd.DataFrame) -> pd.DataFrame:
    """Simulation only: for each TRUE traffic type, what % did we raise an alert on?"""
    if config.LABEL_COL not in results.columns:
        return pd.DataFrame()
    table = results.groupby(config.LABEL_COL).agg(
        connections=("verdict", "size"),
        alerted=("verdict", lambda v: (v != "BENIGN").sum()),
        as_known_attack=("verdict", lambda v: (v == "KNOWN_ATTACK").sum()),
        as_anomaly=("verdict", lambda v: (v == "ANOMALY").sum()),
    )
    table["alert_rate"] = (table["alerted"] / table["connections"]).round(4)
    return table.sort_values("connections", ascending=False)


def format_alert_line(row) -> str:
    """One-line, colour-free console alert (like a SIEM feed)."""
    ts = pd.Timestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    return (f"{ts} [{row['severity']:<8}] {row['alert_id']} {row['threat_type'].upper():<13} "
            f"{row['src_ip']:>15} -> {row['dst_ip']:<15} {row['service']:<9} | {row['reason']}")
