"""
main.py - Command-line entry point for the AI-Powered Threat Detection System.

Usage
-----
    python main.py all                  # generate data -> train -> detect (full demo)
    python main.py generate             # create simulated network traffic
    python main.py train                # train + evaluate models, save charts
    python main.py detect               # scan "live" traffic, raise alerts, build report
    python main.py simulate             # replay live traffic like a real-time SOC feed
    python main.py train --dataset nsl-kdd   # use the real NSL-KDD benchmark instead
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import pandas as pd
from sklearn.model_selection import train_test_split

from src import config
from src import evaluate as ev
from src import visualize as viz
from src.data_loader import generate_synthetic_datasets, load_datasets
from src.detector import (build_incidents, detect, detection_scorecard, format_alert_line,
                          generate_alerts, load_bundle, save_bundle)
from src.models import anomaly_scores, get_feature_importance, train_anomaly_detector, train_classifiers
from src.preprocessing import clean_data, split_features_labels
from src.report import build_report


def banner(text: str) -> None:
    print("\n" + "=" * 78 + f"\n  {text}\n" + "=" * 78)


# --------------------------------------------------------------------------
# Step 1 - generate simulated traffic
# --------------------------------------------------------------------------
def cmd_generate(args) -> None:
    banner("STEP 1 - Simulating network traffic (virtual company network)")
    train, live = generate_synthetic_datasets(n_normal=args.rows)
    for name, df in (("training day", train), ("live day", live)):
        print(f"\n{name}: {len(df):,} connections -> label counts:")
        print(df[config.LABEL_COL].value_counts().to_string())
    print(f"\nSaved: {config.TRAIN_FILE.relative_to(config.ROOT_DIR)}, "
          f"{config.LIVE_FILE.relative_to(config.ROOT_DIR)}")
    print("\nPreview of the training data:")
    with pd.option_context("display.max_columns", 12, "display.width", 160):
        print(train.head(8).to_string())


# --------------------------------------------------------------------------
# Step 2 - train and evaluate
# --------------------------------------------------------------------------
def _binary_scores(m: dict) -> dict:
    b = m["binary"]
    p, r = b["precision"], b["detection_rate_recall"]
    total = b["true_positives"] + b["false_positives"] + b["true_negatives"] + b["false_negatives"]
    return {"Accuracy": (b["true_positives"] + b["true_negatives"]) / total, "Precision": p,
            "Recall": r, "F1": 2 * p * r / (p + r) if p + r else 0.0}


def cmd_train(args) -> None:
    banner(f"STEP 2 - Training models on '{args.dataset}' data")
    train_df, _ = load_datasets(args.dataset)
    df = clean_data(train_df)
    config.ensure_dirs()
    df.to_csv(config.DATA_PROCESSED_DIR / "train_clean.csv", index=False)

    viz.plot_class_distribution(df)
    viz.plot_correlation_heatmap(split_features_labels(df)[0])

    X, y = split_features_labels(df)
    # stratify=y keeps the same attack/normal mix in train and test sets.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, stratify=y, random_state=config.RANDOM_STATE)
    print(f"[split] train={len(X_train):,} rows, test={len(X_test):,} rows")

    classifiers = train_classifiers(X_train, y_train)
    iso, threshold = train_anomaly_detector(X_train, y_train)

    all_metrics, comparison = {"models": {}}, {}
    for name, pipe in classifiers.items():
        y_pred = pipe.predict(X_test)
        m = ev.classification_metrics(y_test, y_pred)
        all_metrics["models"][name] = m
        comparison[name.replace("_", " ").title()] = _binary_scores(m)
        ev.print_summary(name, m)

    rf = classifiers["random_forest"]
    print("\nRandom Forest - per-class report:")
    print(ev.per_class_table(all_metrics["models"]["random_forest"]).to_string())

    test_scores = anomaly_scores(iso, X_test)
    iso_m = ev.anomaly_metrics(y_test, test_scores, threshold)
    all_metrics["isolation_forest"] = {**iso_m, "threshold": threshold}
    flagged = test_scores >= threshold
    is_attack = (y_test != config.NORMAL_LABEL).to_numpy()
    comparison["Isolation Forest"] = {
        "Accuracy": float((flagged == is_attack).mean()), "Precision": iso_m["precision"],
        "Recall": iso_m["detection_rate_recall"],
        "F1": 2 * iso_m["precision"] * iso_m["detection_rate_recall"] /
              max(iso_m["precision"] + iso_m["detection_rate_recall"], 1e-9)}
    print(f"\n=== isolation_forest (unsupervised, never saw an attack label) ===\n  "
          + ", ".join(f"{k}={v}" for k, v in iso_m.items()))

    labels = sorted(y.unique(), key=lambda c: (c != config.NORMAL_LABEL, c))
    viz.plot_confusion_matrix(y_test, rf.predict(X_test), labels)
    viz.plot_model_comparison(pd.DataFrame(comparison).T)
    viz.plot_feature_importance(get_feature_importance(rf))
    viz.plot_anomaly_scores(test_scores, y_test, threshold)

    all_metrics["model_comparison"] = comparison
    all_metrics["dataset"] = {"source": args.dataset, "rows": len(df),
                              "class_counts": y.value_counts().to_dict()}
    ev.save_metrics(all_metrics)
    save_bundle(rf, iso, threshold)


# --------------------------------------------------------------------------
# Step 3 - detect threats in "live" traffic
# --------------------------------------------------------------------------
def cmd_detect(args) -> None:
    banner("STEP 3 - Threat detection on live traffic")
    bundle = load_bundle()
    _, live_df = load_datasets(args.dataset)
    live = clean_data(live_df)

    start = time.perf_counter()
    results = detect(live, bundle)
    elapsed = time.perf_counter() - start
    print(f"[detect] scored {len(results):,} connections in {elapsed:.2f}s "
          f"({len(results) / elapsed:,.0f} connections/sec)")

    alerts = generate_alerts(results)
    incidents = build_incidents(alerts)
    scorecard = detection_scorecard(results)

    alerts.to_csv(config.OUTPUTS_DIR / "alerts.csv", index=False)
    incidents.to_csv(config.OUTPUTS_DIR / "incidents.csv", index=False)
    results.to_csv(config.OUTPUTS_DIR / "predictions.csv", index=False)
    alerts.head(200).to_json(config.OUTPUTS_DIR / "alerts_sample.json",
                             orient="records", indent=2, date_format="iso")
    print("[save] outputs/alerts.csv, outputs/incidents.csv, outputs/predictions.csv, "
          "outputs/alerts_sample.json")

    print(f"\nVerdicts: {results['verdict'].value_counts().to_dict()}")
    print(f"Alerts by severity: {alerts['severity'].value_counts().to_dict()}")
    print("\nSample alerts (first per threat type):")
    for _, row in alerts.groupby("threat_type").head(1).iterrows():
        print("  " + format_alert_line(row))

    print("\nIncidents (top 10):")
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print(incidents.head(10).to_string(index=False))
    if not scorecard.empty:
        print("\nDetection scorecard vs ground truth:")
        print(scorecard.to_string())

    viz.plot_attack_timeline(results)
    viz.plot_alerts_by_severity(alerts)
    viz.plot_top_attackers(alerts)
    viz.plot_anomaly_scatter(results, bundle)
    viz.plot_detection_scorecard(scorecard)
    viz.plot_anomaly_scores(results["anomaly_score"].to_numpy(), results[config.LABEL_COL],
                            bundle["anomaly_threshold"], filename="12_live_anomaly_scores.png",
                            title="Live Traffic Anomaly Scores (note the unseen zero-day class)")

    with open(config.METRICS_FILE, encoding="utf-8") as fh:
        metrics = json.load(fh)
    metrics["live_detection"] = {
        "connections": len(results), "alerts": len(alerts), "incidents": len(incidents),
        "scorecard": scorecard.reset_index().to_dict(orient="records")}
    ev.save_metrics(metrics)
    build_report(metrics, alerts, incidents, scorecard, len(results))


# --------------------------------------------------------------------------
# Step 4 - real-time style simulation
# --------------------------------------------------------------------------
def cmd_simulate(args) -> None:
    banner("REAL-TIME SIMULATION - replaying live traffic in 1-hour windows")
    bundle = load_bundle()
    _, live_df = load_datasets(args.dataset)
    live = clean_data(live_df, verbose=False)
    live["window"] = live["timestamp"].dt.floor("1h")

    total_alerts = 0
    for window, batch in live.groupby("window"):
        results = detect(batch.drop(columns="window"), bundle)
        alerts = generate_alerts(results, start_id=total_alerts + 1)
        total_alerts += len(alerts)
        status = "ALL CLEAR" if alerts.empty else f"{len(alerts)} ALERTS"
        print(f"\n[{window:%H:%M}] {len(batch):>5} connections | {status}")
        if not alerts.empty:
            summary = alerts.groupby(["threat_type", "severity"]).size()
            for (threat, sev), n in summary.items():
                print(f"    >> {sev:<8} {threat:<13} x{n}")
            for _, row in alerts.head(args.show).iterrows():
                print("       " + format_alert_line(row))
        time.sleep(args.delay)
    print(f"\nSimulation finished: {len(live):,} connections, {total_alerts:,} alerts.")


def cmd_all(args) -> None:
    if args.dataset == "synthetic":
        cmd_generate(args)
    cmd_train(args)
    cmd_detect(args)
    banner("DONE - open outputs/soc_report.html and the images/ folder")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="AI-Powered Cybersecurity Threat Detection System")
    parser.add_argument("command", choices=["generate", "train", "detect", "simulate", "all"])
    parser.add_argument("--dataset", choices=["synthetic", "nsl-kdd"], default="synthetic",
                        help="data source (default: synthetic simulator)")
    parser.add_argument("--rows", type=int, default=20000,
                        help="normal connections to simulate for the training day")
    parser.add_argument("--delay", type=float, default=0.3, help="seconds between windows in simulate")
    parser.add_argument("--show", type=int, default=3, help="alerts to print per window in simulate")
    return parser.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    {"generate": cmd_generate, "train": cmd_train, "detect": cmd_detect,
     "simulate": cmd_simulate, "all": cmd_all}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
