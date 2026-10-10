"""
visualize.py - All charts for the project (saved as PNG into images/).

These images are your PROOF OF WORK: they go into the README and show a
recruiter, in 10 seconds, that the system really detects attacks.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")                      # render to files, no window needed
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.decomposition import PCA
from sklearn.metrics import confusion_matrix

from src import config

# One fixed colour per threat type, reused in every chart for consistency.
THREAT_COLORS = {
    "normal": "#4C78A8", "dos": "#E45756", "probe": "#F58518", "brute_force": "#B279A2",
    "exfiltration": "#9D755D", "anomaly": "#2CA02C", "r2l": "#EECA3B", "u2r": "#72B7B2",
}
SEVERITY_COLORS = {"LOW": "#9ecae1", "MEDIUM": "#F58518", "HIGH": "#E45756", "CRITICAL": "#7B1E1E"}

sns.set_theme(style="whitegrid", context="notebook")


def _save(fig, name: str) -> None:
    config.IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    path = config.IMAGES_DIR / name
    fig.tight_layout()
    fig.savefig(path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot] {path.relative_to(config.ROOT_DIR)}")


def _color(label: str) -> str:
    return THREAT_COLORS.get(label, "#888888")


# --------------------------------------------------------------------------
# Training-time charts
# --------------------------------------------------------------------------
def plot_class_distribution(df: pd.DataFrame) -> None:
    counts = df[config.LABEL_COL].value_counts()
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(counts.index, counts.values, color=[_color(c) for c in counts.index])
    for i, v in enumerate(counts.values):
        ax.text(i, v, f"{v:,}\n({v / counts.sum():.1%})", ha="center", va="bottom", fontsize=9)
    ax.set_title("Traffic Class Distribution (training data)")
    ax.set_ylabel("Connections")
    ax.set_ylim(0, counts.max() * 1.18)
    _save(fig, "01_class_distribution.png")


def plot_correlation_heatmap(df: pd.DataFrame) -> None:
    numeric = df.select_dtypes("number").loc[:, lambda d: d.std() > 0]
    fig, ax = plt.subplots(figsize=(11, 9))
    sns.heatmap(numeric.corr(), cmap="coolwarm", center=0, ax=ax, cbar_kws={"shrink": 0.7})
    ax.set_title("Feature Correlation Heatmap")
    _save(fig, "02_feature_correlation.png")


def plot_confusion_matrix(y_true, y_pred, labels, name: str = "random_forest") -> None:
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    cm_pct = cm / cm.sum(axis=1, keepdims=True)
    annot = np.array([[f"{cm[i, j]:,}\n{cm_pct[i, j]:.1%}" for j in range(len(labels))]
                      for i in range(len(labels))])
    fig, ax = plt.subplots(figsize=(8, 6.5))
    sns.heatmap(cm_pct, annot=annot, fmt="", cmap="Blues", xticklabels=labels,
                yticklabels=labels, ax=ax, vmin=0, vmax=1, cbar_kws={"label": "Row %"})
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix - {name.replace('_', ' ').title()}")
    _save(fig, f"03_confusion_matrix_{name}.png")


def plot_model_comparison(summary: pd.DataFrame) -> None:
    """summary: index = model name, columns = metric names (0-1)."""
    fig, ax = plt.subplots(figsize=(9, 4.8))
    summary.plot(kind="bar", ax=ax, width=0.8, colormap="tab10", rot=0)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison (attack vs normal, held-out test set)")
    ax.legend(loc="lower right", fontsize=9)
    for container in ax.containers:
        ax.bar_label(container, fmt="%.2f", fontsize=7)
    _save(fig, "04_model_comparison.png")


def plot_feature_importance(importance: pd.Series) -> None:
    fig, ax = plt.subplots(figsize=(8, 5.5))
    importance.sort_values().plot(kind="barh", ax=ax, color="#4C78A8")
    ax.set_title("Top Features Used by Random Forest")
    ax.set_xlabel("Importance")
    _save(fig, "05_feature_importance.png")


def plot_anomaly_scores(scores, y_true, threshold: float, filename="06_anomaly_score_distribution.png",
                        title="Isolation Forest Anomaly Scores") -> None:
    y_true = pd.Series(y_true).reset_index(drop=True)
    fig, ax = plt.subplots(figsize=(9, 4.8))
    bins = np.linspace(np.min(scores), np.max(scores), 60)
    for label in y_true.unique():
        ax.hist(scores[y_true == label], bins=bins, alpha=0.6, label=label, color=_color(label))
    ax.axvline(threshold, color="black", linestyle="--", label=f"threshold = {threshold:.3f}")
    ax.set_yscale("log")
    ax.set_xlabel("Anomaly score (higher = more suspicious)")
    ax.set_ylabel("Connections (log scale)")
    ax.set_title(title)
    ax.legend(fontsize=8)
    _save(fig, filename)


# --------------------------------------------------------------------------
# Detection / SOC dashboard charts
# --------------------------------------------------------------------------
def plot_attack_timeline(results: pd.DataFrame) -> None:
    """Traffic volume vs alerts over the day - attack bursts stand out as spikes."""
    r = results.set_index(pd.to_datetime(results["timestamp"]))
    total = r["verdict"].resample("15min").size()
    alerts = (r[r["verdict"] != "BENIGN"].groupby("threat_type")["verdict"]
              .resample("15min").size().unstack(0).reindex(total.index).fillna(0))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7), sharex=True,
                                   gridspec_kw={"height_ratios": [1, 1.6]})
    ax1.fill_between(total.index, total.values, color="#4C78A8", alpha=0.4)
    ax1.set_ylabel("All connections")
    ax1.set_title("Live Traffic Monitoring - 24 h Timeline (15-min buckets)")
    bottom = np.zeros(len(alerts))
    for col in alerts.columns:
        ax2.bar(alerts.index, alerts[col].values, width=0.01, bottom=bottom,
                color=_color(col), label=col, align="edge")
        bottom += alerts[col].values
    ax2.set_ylabel("Alerts raised")
    ax2.legend(title="Threat type", ncol=3, fontsize=8)
    fig.autofmt_xdate()
    _save(fig, "07_attack_timeline.png")


def plot_alerts_by_severity(alerts: pd.DataFrame) -> None:
    order = [s for s in reversed(config.SEVERITY_ORDER) if s in alerts["severity"].unique()]
    pivot = alerts.groupby(["severity", "threat_type"]).size().unstack(fill_value=0).reindex(order)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    pivot.plot(kind="barh", stacked=True, ax=ax, color=[_color(c) for c in pivot.columns])
    ax.invert_yaxis()
    ax.set_xlabel("Number of alerts")
    ax.set_ylabel("")
    ax.set_title("Alerts by Severity and Threat Type")
    ax.legend(title="Threat type", fontsize=8)
    _save(fig, "08_alerts_by_severity.png")


def plot_top_attackers(alerts: pd.DataFrame, top_n: int = 10) -> None:
    top = (alerts.groupby(["src_ip", "threat_type"]).size().reset_index(name="alerts")
           .sort_values("alerts", ascending=False).head(top_n))
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(top["src_ip"] + "  (" + top["threat_type"] + ")", top["alerts"],
            color=[_color(t) for t in top["threat_type"]])
    ax.invert_yaxis()
    ax.set_xlabel("Alerts")
    ax.set_title(f"Top {top_n} Suspicious Source IPs")
    _save(fig, "09_top_attacker_ips.png")


def plot_anomaly_scatter(results: pd.DataFrame, bundle: dict, sample: int = 6000) -> None:
    """Project every connection to 2-D with PCA. Alerts form clusters away from normal."""
    s = results.sample(min(sample, len(results)), random_state=config.RANDOM_STATE)
    from src.preprocessing import split_features_labels
    X, _ = split_features_labels(s[[c for c in s.columns if c not in (
        "predicted_type", "confidence", "anomaly_score", "is_anomalous", "verdict",
        "threat_type", "severity")]])
    pipe = bundle["classifier"]
    encoded = pipe.named_steps["preprocess"].transform(pipe.named_steps["features"].transform(X))
    # Rare features (e.g. wrong_fragment) get huge scaled values; clipping keeps
    # one feature from stretching the whole picture.
    encoded = np.clip(encoded, -4, 4)
    points = PCA(n_components=2, random_state=config.RANDOM_STATE).fit_transform(encoded)

    fig, ax = plt.subplots(figsize=(9, 6.5))
    for verdict, marker, size, alpha in [("BENIGN", "o", 8, 0.35), ("KNOWN_ATTACK", "^", 14, 0.7),
                                         ("ANOMALY", "X", 60, 0.95)]:
        m = (s["verdict"] == verdict).to_numpy()
        colors = [_color(t) if verdict != "BENIGN" else "#B0B0B0" for t in s.loc[m, "threat_type"]]
        ax.scatter(points[m, 0], points[m, 1], c=colors, s=size, marker=marker, alpha=alpha,
                   label=verdict, edgecolors="black" if verdict == "ANOMALY" else "none", linewidths=0.4)
    ax.set_xlabel("Principal component 1")
    ax.set_ylabel("Principal component 2")
    ax.set_title("Network Connections in 2-D (PCA) - grey = benign, X = anomaly alert")
    ax.legend()
    _save(fig, "10_anomaly_scatter_pca.png")


def plot_detection_scorecard(scorecard: pd.DataFrame) -> None:
    if scorecard.empty:
        return
    sc = scorecard.sort_values("alert_rate")
    fig, ax = plt.subplots(figsize=(9, 4.5))
    bars = ax.barh(sc.index, sc["alert_rate"], color=[_color(i) for i in sc.index])
    ax.bar_label(bars, labels=[f"{v:.1%}" for v in sc["alert_rate"]], padding=3, fontsize=9)
    ax.set_xlim(0, 1.12)
    ax.set_xlabel("Share of connections that raised an alert")
    ax.set_title("Live Simulation Scorecard (normal should be LOW, attacks HIGH)")
    _save(fig, "11_detection_scorecard.png")
