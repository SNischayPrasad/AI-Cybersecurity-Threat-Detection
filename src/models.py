"""
models.py - Build and train the AI models.

We use a HYBRID design, exactly like commercial IDS/NDR products:

* Supervised classifier (Random Forest)  -> recognises KNOWN attack types
  it has seen examples of (DoS, probe, brute force, exfiltration).
* Unsupervised anomaly detector (Isolation Forest) -> learns what NORMAL
  traffic looks like and flags anything unusual, including ZERO-DAY attacks
  that no labelled example exists for.
* Logistic Regression is trained as a simple baseline to compare against.
"""

from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from src import config
from src.feature_engineering import FeatureEngineer, add_engineered_features, build_preprocessor


def _make_pipeline(X_train: pd.DataFrame, estimator) -> Pipeline:
    """feature engineering -> encode/scale -> model, all in ONE object."""
    preprocessor = build_preprocessor(add_engineered_features(X_train.head(50)))
    return Pipeline([
        ("features", clone(FeatureEngineer)),
        ("preprocess", preprocessor),
        ("model", estimator),
    ])


def get_classifiers() -> dict:
    return {
        "logistic_regression": LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=config.RANDOM_STATE),
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=None, min_samples_leaf=2,
            class_weight="balanced",          # attacks are rarer than normal traffic
            n_jobs=-1, random_state=config.RANDOM_STATE),
    }


def train_classifiers(X_train: pd.DataFrame, y_train: pd.Series) -> dict[str, Pipeline]:
    """Train every classifier and return {name: fitted_pipeline}."""
    trained = {}
    for name, estimator in get_classifiers().items():
        start = time.perf_counter()
        pipe = _make_pipeline(X_train, estimator)
        pipe.fit(X_train, y_train)
        print(f"[train] {name:<20} trained on {len(X_train):,} rows in {time.perf_counter() - start:.1f}s")
        trained[name] = pipe
    return trained


def train_anomaly_detector(X_train: pd.DataFrame, y_train: pd.Series) -> tuple[Pipeline, float]:
    """
    Fit Isolation Forest on NORMAL traffic only, then choose a threshold.

    Isolation Forest idea: anomalies are "few and different", so they get
    isolated by random splits very quickly (short path in the trees).
    score_samples() returns higher = more normal, so we negate it to get an
    anomaly score where higher = more suspicious.
    """
    X_normal = X_train[y_train == config.NORMAL_LABEL]
    detector = IsolationForest(n_estimators=300, contamination="auto",
                               random_state=config.RANDOM_STATE, n_jobs=-1)
    pipe = _make_pipeline(X_normal, detector)
    pipe.fit(X_normal)

    normal_scores = -pipe.score_samples(X_normal)
    threshold = float(np.percentile(normal_scores, config.ANOMALY_PERCENTILE))
    print(f"[train] isolation_forest      trained on {len(X_normal):,} NORMAL rows, "
          f"threshold={threshold:.4f} (p{config.ANOMALY_PERCENTILE:g} of normal scores)")
    return pipe, threshold


def anomaly_scores(detector: Pipeline, X: pd.DataFrame) -> np.ndarray:
    """Higher = more anomalous."""
    return -detector.score_samples(X)


def get_feature_importance(pipe: Pipeline, top_n: int = 15) -> pd.Series:
    """Which features did the Random Forest rely on most? (explainability)"""
    names = pipe.named_steps["preprocess"].get_feature_names_out()
    importances = pipe.named_steps["model"].feature_importances_
    return pd.Series(importances, index=names).sort_values(ascending=False).head(top_n)
