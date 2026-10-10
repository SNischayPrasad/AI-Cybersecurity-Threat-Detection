"""
evaluate.py - Measure how good the models are.

Why not only accuracy? With 75% normal traffic, a useless model that says
"normal" for everything is 75% accurate. Security teams care about:

* Precision - of the alerts we raised, how many were real attacks?
              (low precision = alert fatigue, analysts ignore alerts)
* Recall    - of the real attacks, how many did we catch?
              (low recall = breaches go unnoticed - the worst outcome)
* F1 score  - balance of the two.
* False Positive Rate - % of normal traffic wrongly flagged.
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)

from src import config


def classification_metrics(y_true, y_pred) -> dict:
    """Multi-class metrics + an 'attack vs normal' binary view."""
    y_true = pd.Series(y_true).reset_index(drop=True)
    y_pred = pd.Series(y_pred).reset_index(drop=True)
    true_attack = y_true != config.NORMAL_LABEL
    pred_attack = y_pred != config.NORMAL_LABEL
    tn, fp, fn, tp = confusion_matrix(true_attack, pred_attack, labels=[False, True]).ravel()

    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision_macro": round(precision_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "recall_macro": round(recall_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "f1_macro": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "f1_weighted": round(f1_score(y_true, y_pred, average="weighted", zero_division=0), 4),
        "binary": {
            "detection_rate_recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "true_positives": int(tp), "false_positives": int(fp),
            "true_negatives": int(tn), "false_negatives": int(fn),
        },
        "per_class": classification_report(y_true, y_pred, output_dict=True, zero_division=0),
    }


def anomaly_metrics(y_true, scores: np.ndarray, threshold: float) -> dict:
    """How well does the Isolation Forest separate attacks from normal on its own?"""
    is_attack = (pd.Series(y_true) != config.NORMAL_LABEL).astype(int).to_numpy()
    flagged = scores >= threshold
    tp = int((flagged & (is_attack == 1)).sum())
    fp = int((flagged & (is_attack == 0)).sum())
    fn = int((~flagged & (is_attack == 1)).sum())
    tn = int((~flagged & (is_attack == 0)).sum())
    return {
        "roc_auc": round(roc_auc_score(is_attack, scores), 4),
        "detection_rate_recall": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
    }


def print_summary(name: str, metrics: dict) -> None:
    b = metrics["binary"]
    print(f"\n=== {name} ===")
    print(f"  Accuracy            : {metrics['accuracy']:.4f}")
    print(f"  Precision (macro)   : {metrics['precision_macro']:.4f}")
    print(f"  Recall (macro)      : {metrics['recall_macro']:.4f}")
    print(f"  F1 score (macro)    : {metrics['f1_macro']:.4f}")
    print(f"  Attack detection    : {b['detection_rate_recall']:.2%}  |  "
          f"False positive rate: {b['false_positive_rate']:.2%}")


def per_class_table(metrics: dict) -> pd.DataFrame:
    rows = {k: v for k, v in metrics["per_class"].items()
            if k not in ("accuracy", "macro avg", "weighted avg")}
    return pd.DataFrame(rows).T[["precision", "recall", "f1-score", "support"]].round(4)


def save_metrics(all_metrics: dict, path=config.METRICS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(all_metrics, fh, indent=2, default=str)
    print(f"[save] metrics -> {path.relative_to(config.ROOT_DIR)}")
