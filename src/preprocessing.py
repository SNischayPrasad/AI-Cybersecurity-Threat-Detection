"""
preprocessing.py - Data cleaning.

Raw security logs are messy: duplicate rows, missing values, wrong data
types, impossible negative byte counts. A model trained on dirty data
learns dirty patterns, so we clean first.
"""

from __future__ import annotations

import pandas as pd

from src import config


def clean_data(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """Return a cleaned copy of the dataframe and print what was fixed."""
    df = df.copy()
    report = {"rows_in": len(df)}

    # 1. Remove exact duplicate rows (the same log line shipped twice by a collector).
    feature_cols = [c for c in df.columns if c not in config.META_COLS]
    before = len(df)
    df = df.drop_duplicates()
    report["exact_duplicates_removed"] = before - len(df)

    # 2. Parse timestamps if present.
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # 3. Fix data types: categoricals as text, everything else numeric.
    for col in config.CATEGORICAL_COLS:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.lower().replace({"nan": "unknown"})

    numeric_cols = [c for c in feature_cols
                    if c not in config.CATEGORICAL_COLS and c != config.LABEL_COL]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # 4. Missing values: median for numbers (robust to outliers), "unknown" for text.
    report["missing_values_filled"] = int(df[numeric_cols].isna().sum().sum())
    df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

    # 5. Impossible values: bytes/counts/durations can never be negative.
    df[numeric_cols] = df[numeric_cols].clip(lower=0)

    # 6. Rates must be in [0, 1].
    rate_cols = [c for c in numeric_cols if c.endswith("_rate")]
    df[rate_cols] = df[rate_cols].clip(0, 1)

    # 7. Normalise labels.
    if config.LABEL_COL in df.columns:
        df[config.LABEL_COL] = df[config.LABEL_COL].astype(str).str.strip().str.lower()

    report["rows_out"] = len(df)
    if verbose:
        print("[clean] " + ", ".join(f"{k}={v}" for k, v in report.items()))
    return df.reset_index(drop=True)


def split_features_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Separate the model inputs (X) from the answer (y). Meta columns are dropped."""
    drop = [c for c in config.META_COLS + [config.LABEL_COL] if c in df.columns]
    X = df.drop(columns=drop)
    y = df[config.LABEL_COL] if config.LABEL_COL in df.columns else None
    return X, y
