"""
feature_engineering.py - Turn raw columns into signals that reveal attacks.

Two jobs:
1. add_engineered_features(): create NEW columns that encode security
   domain knowledge (e.g. "bytes sent vs bytes received" exposes data theft).
2. build_preprocessor(): a scikit-learn ColumnTransformer that one-hot
   encodes text columns and scales numeric columns. Because it is part of
   the saved model pipeline, the exact same transformation is applied at
   training time and at detection time (no "training/serving skew").
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from src import config


def add_engineered_features(X: pd.DataFrame) -> pd.DataFrame:
    """Add security-focused features. Works on synthetic and NSL-KDD data."""
    X = X.copy()

    # Traffic volume. Log-scale tames huge byte values (1 B ... 50 MB).
    X["total_bytes"] = X["src_bytes"] + X["dst_bytes"]
    X["log_src_bytes"] = np.log1p(X["src_bytes"])
    X["log_dst_bytes"] = np.log1p(X["dst_bytes"])

    # Upload/download ratio: exfiltration sends far more than it receives.
    X["bytes_ratio"] = np.log1p(X["src_bytes"]) - np.log1p(X["dst_bytes"])

    # Combined error signal: floods and scans create many failed handshakes.
    X["total_error_rate"] = X["serror_rate"] + X["rerror_rate"]

    # Any failed login at all is suspicious; many in a row = brute force.
    X["has_failed_login"] = (X["num_failed_logins"] > 0).astype(int)

    # Zero-payload connections are the hallmark of SYN floods and scans.
    X["zero_payload"] = (X["src_bytes"] == 0).astype(int)

    # Share of connections that go to the same service (focus vs. spread).
    X["srv_focus_ratio"] = X["srv_count"] / (X["count"] + 1)

    # Packet-level malformation (fragment / urgent abuse).
    X["malformed_packet"] = ((X["wrong_fragment"] > 0) | (X["urgent"] > 0)).astype(int)
    return X


def build_preprocessor(X_sample: pd.DataFrame) -> ColumnTransformer:
    """Create the encoding/scaling step from a sample of (engineered) features."""
    categorical = [c for c in config.CATEGORICAL_COLS if c in X_sample.columns]
    numeric = [c for c in X_sample.columns if c not in categorical]
    return ColumnTransformer(
        transformers=[
            # handle_unknown="ignore": a never-seen service at detection time
            # becomes all-zeros instead of crashing the pipeline.
            ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
            ("numeric", StandardScaler(), numeric),
        ],
        verbose_feature_names_out=False,
    )


# Wrap add_engineered_features so it can sit inside a sklearn Pipeline.
FeatureEngineer = FunctionTransformer(add_engineered_features, validate=False)
