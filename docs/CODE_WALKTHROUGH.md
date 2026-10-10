# G. Code Walkthrough - every file explained

The full source code is in the repo (all files are commented line by line). This document explains
**what each file does, why it's designed that way, and what to say about it in an interview.**

Execution order when you run `python main.py all`:

```
main.py
 ├─ cmd_generate → data_loader.generate_synthetic_datasets → simulator.generate_traffic
 ├─ cmd_train    → data_loader.load_datasets → preprocessing.clean_data
 │                 → models.train_classifiers / train_anomaly_detector (uses feature_engineering)
 │                 → evaluate.* → visualize.* → detector.save_bundle
 └─ cmd_detect   → detector.load_bundle → detector.detect → generate_alerts → build_incidents
                   → visualize.* → report.build_report
```

---

## `src/config.py` - settings

* All folder paths are built from `ROOT_DIR`, so the project runs from any location on any OS.
* `META_COLS` (`timestamp, src_ip, dst_ip`) are kept for alerts but **excluded from model input**.
  If the model saw IPs it would memorise *who* attacked instead of learning *how* attacks behave.
* `ANOMALY_PERCENTILE = 99` → the anomaly threshold accepts ~1% false alarms on normal traffic.
* `SEVERITY_BY_TYPE`, `MITRE_BY_TYPE`, `RECOMMENDED_ACTION` turn ML output into SOC language.

**Interview line:** *"I centralised configuration so thresholds can be tuned without touching logic - the same way detection rules are tuned in a SIEM."*

## `src/simulator.py` - virtual attack simulator

* One function per behaviour: `simulate_normal`, `simulate_dos`, `simulate_probe`, `simulate_brute_force`, `simulate_exfiltration`, `simulate_zero_day`.
* Each draws feature values from probability distributions chosen to match the real attack mechanics
  (e.g. SYN flood → `flag="S0"`, `serror_rate ~ Beta(20,1.5)` ≈ 0.93).
* `_business_hours_timestamps` makes normal traffic follow a working-day curve.
* Realism: grey benign traffic, stealthy attack variants, `_blend_benign_flows` (2% label noise).
* `generate_traffic(seed=...)` randomises attack windows per day; `include_zero_day=True` only for the live day.

**Interview line:** *"Without access to a corporate network I modelled each attack from its protocol-level mechanics, and deliberately added noise and stealthy variants so the problem isn't trivially separable."*

## `src/data_loader.py` - data sources

* `generate_synthetic_datasets()` → Day 1 (train) & Day 2 (live) CSVs.
* `load_nsl_kdd()` → downloads NSL-KDD once, adds column names (the raw file has no header),
  maps ~40 attack names to families (`neptune→dos`, `guess_passwd→brute_force`...), and relabels
  families unseen in training as `anomaly`.
* `load_datasets(source)` → one entry point for both.

## `src/preprocessing.py` - cleaning

`clean_data()` steps: drop duplicates → parse timestamps → normalise text categories → coerce
numerics → median-fill missing values → clip negatives → clip rates to [0, 1] → normalise labels.
Prints a one-line cleaning report. `split_features_labels()` returns `X` (features only) and `y`.

## `src/feature_engineering.py` - features

| New feature | Formula | Catches |
|---|---|---|
| `total_bytes` | src + dst | volume anomalies |
| `log_src_bytes`, `log_dst_bytes` | log(1+x) | tames 1 B … 50 MB range |
| `bytes_ratio` | log src − log dst | exfiltration (uploads ≫ downloads) |
| `total_error_rate` | serror + rerror | floods & scans |
| `has_failed_login` | failed_logins > 0 | brute force |
| `zero_payload` | src_bytes == 0 | SYN floods, scans |
| `srv_focus_ratio` | srv_count / (count+1) | focused vs. spread activity |
| `malformed_packet` | wrong_fragment>0 or urgent>0 | packet-level exploits |

`build_preprocessor()` → `ColumnTransformer` with `OneHotEncoder(handle_unknown="ignore")` for
`protocol_type, service, flag` and `StandardScaler` for numerics. `FeatureEngineer` wraps the
feature function so it can sit inside a Pipeline.

**Interview line:** *"Feature engineering and encoding live inside the saved sklearn Pipeline, so detection uses exactly the same transformations as training - no training/serving skew."*

## `src/models.py` - models

* `_make_pipeline()` → `Pipeline([features → preprocess → model])`.
* `get_classifiers()` → Logistic Regression (baseline) and Random Forest (200 trees, `class_weight="balanced"`, `min_samples_leaf=2`).
* `train_anomaly_detector()` → Isolation Forest fit **only on normal rows**; threshold = 99th percentile of normal anomaly scores.
* `anomaly_scores()` → `-score_samples()` so higher = more suspicious.
* `get_feature_importance()` → explainability chart.

## `src/evaluate.py` - metrics

* `classification_metrics()` → accuracy, macro precision/recall/F1, weighted F1, per-class report,
  plus binary attack-vs-normal TP/FP/TN/FN, detection rate and false-positive rate.
* `anomaly_metrics()` → ROC-AUC, recall, precision, FPR for Isolation Forest.
* `save_metrics()` → `outputs/metrics.json` (machine-readable proof).

**Why macro averages?** Macro gives the rare `exfiltration` class equal weight to `normal`; weighted averages can hide a model that ignores rare attacks.

## `src/detector.py` - detection engine

1. `detect()` → for each row: RF class + confidence, IF score, `is_anomalous`.
2. Verdict: `KNOWN_ATTACK` if RF predicts an attack with ≥ 50% confidence; else `ANOMALY` if score ≥ threshold; else `BENIGN`.
3. Severity: base by type, lowered when unsure, escalated for extreme anomalies (vectorised with pandas).
4. `generate_alerts()` → alert id, MITRE technique, human-readable reason, recommended action.
5. `build_incidents()` → groups by `(threat_type, src_ip)` - 3,701 alerts become 110 incidents.
6. `detection_scorecard()` → compares verdicts with ground-truth labels (simulation only).
7. `save_bundle()/load_bundle()` → one joblib file with both models + threshold.

## `src/visualize.py` - charts

12 functions, one per chart, with a fixed colour per threat type. Uses the `Agg` backend so charts
save to files without needing a display (works on servers/CI). See the list in [GITHUB_GUIDE.md](GITHUB_GUIDE.md#13-screenshots--outputs--demo-assets).

## `src/report.py` - HTML SOC report

Builds `outputs/soc_report.html` with KPI tiles, incidents table, top alerts, scorecard and all charts
embedded as base64 - a single file you can attach to an email or LinkedIn post.

## `main.py` - command line

`argparse` with sub-commands `generate | train | detect | simulate | all` and options
`--dataset {synthetic,nsl-kdd}`, `--rows`, `--delay`, `--show`. Each command is a small function
that orchestrates the modules above and prints progress.

## `tests/test_pipeline.py` - automated tests

| Test | Guarantees |
|---|---|
| `test_simulator_produces_all_traffic_types` | all 6 traffic types + context columns exist |
| `test_cleaning_handles_dirty_rows` | duplicates removed, NaN filled, negatives clipped |
| `test_engineered_features_have_no_nans` | feature engineering is numerically safe |
| `test_classifier_detects_known_attacks` | > 90% of known attacks alerted |
| `test_false_positive_rate_is_low` | < 5% of normal traffic alerted |
| `test_zero_day_is_caught_by_anomaly_detector` | > 70% of zero-day flagged as ANOMALY |
| `test_alerts_and_incidents_are_well_formed` | unique ids, valid severities, MITRE present, incidents add up |

## `notebooks/01_exploratory_data_analysis.ipynb`

EDA: shape & types, class balance, attack fingerprint table (mean features per class), attacks per
hour, and running the trained detector on live traffic with a `label × verdict` crosstab.
