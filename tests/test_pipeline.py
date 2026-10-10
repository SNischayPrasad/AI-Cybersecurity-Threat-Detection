"""
Automated tests - run with:  python -m pytest -q

They train on a SMALL simulated dataset so the whole suite runs in seconds.
Tests are proof to reviewers that the code is reliable, not just a notebook.
"""

import pandas as pd
import pytest

from src import config
from src.detector import build_incidents, detect, generate_alerts
from src.feature_engineering import add_engineered_features
from src.models import train_anomaly_detector, train_classifiers
from src.preprocessing import clean_data, split_features_labels
from src.simulator import generate_traffic


@pytest.fixture(scope="module")
def small_data():
    train = clean_data(generate_traffic(n_normal=2000, seed=1), verbose=False)
    live = clean_data(generate_traffic(n_normal=1000, seed=2, include_zero_day=True), verbose=False)
    return train, live


@pytest.fixture(scope="module")
def bundle(small_data):
    train, _ = small_data
    X, y = split_features_labels(train)
    rf = train_classifiers(X, y)["random_forest"]
    iso, threshold = train_anomaly_detector(X, y)
    return {"classifier": rf, "anomaly_detector": iso, "anomaly_threshold": threshold}


def test_simulator_produces_all_traffic_types(small_data):
    _, live = small_data
    assert set(live["label"]) == {"normal", "dos", "probe", "brute_force", "exfiltration", "anomaly"}
    assert {"timestamp", "src_ip", "dst_ip"}.issubset(live.columns)


def test_cleaning_handles_dirty_rows():
    df = generate_traffic(n_normal=200, seed=3)
    dirty = pd.concat([df, df.head(5)], ignore_index=True)       # duplicates
    dirty.loc[100, "src_bytes"] = None                            # missing value
    dirty.loc[101, "dst_bytes"] = -50                             # impossible value
    clean = clean_data(dirty, verbose=False)
    assert len(clean) == len(df)
    assert clean["src_bytes"].isna().sum() == 0
    assert (clean["dst_bytes"] >= 0).all()


def test_engineered_features_have_no_nans(small_data):
    train, _ = small_data
    X, _ = split_features_labels(train)
    features = add_engineered_features(X)
    assert {"bytes_ratio", "total_error_rate", "zero_payload"}.issubset(features.columns)
    assert not features.select_dtypes("number").isna().any().any()


def test_classifier_detects_known_attacks(small_data, bundle):
    _, live = small_data
    results = detect(live, bundle)
    attacks = results[~results["label"].isin(["normal", "anomaly"])]
    detection_rate = (attacks["verdict"] != "BENIGN").mean()
    assert detection_rate > 0.90


def test_false_positive_rate_is_low(small_data, bundle):
    _, live = small_data
    results = detect(live, bundle)
    normal = results[results["label"] == "normal"]
    assert (normal["verdict"] != "BENIGN").mean() < 0.05


def test_zero_day_is_caught_by_anomaly_detector(small_data, bundle):
    _, live = small_data
    results = detect(live, bundle)
    zero_day = results[results["label"] == "anomaly"]
    assert (zero_day["verdict"] == "ANOMALY").mean() > 0.70


def test_alerts_and_incidents_are_well_formed(small_data, bundle):
    _, live = small_data
    alerts = generate_alerts(detect(live, bundle))
    assert alerts["alert_id"].is_unique
    assert set(alerts["severity"]).issubset(config.SEVERITY_ORDER)
    assert alerts["mitre_attack"].notna().all()
    incidents = build_incidents(alerts)
    assert incidents["alert_count"].sum() == len(alerts)
