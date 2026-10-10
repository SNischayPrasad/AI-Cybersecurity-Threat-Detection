# Project Guide - AI-Powered Cybersecurity Threat Detection System

This guide covers the concepts, design decisions, phase-by-phase build plan, the virtual
attack simulation, and how to run and interpret everything.

| Section | Content |
|---|---|
| [A. Project explanation](#a-project-explanation) | What it is, why it matters, how companies use it |
| [B. Tech stack options](#b-tech-stack-options) | Easy / intermediate / advanced |
| [C. Selected approach](#c-selected-approach) | What we built and why |
| [D. Architecture](#d-architecture) | Block diagram, modules, data flow |
| [Implementation plan](#implementation-plan-10-phases) | 10 phases: what / why / output / mistakes / verify |
| [H. Virtual simulation](#h-virtual-simulation-of-cyber-threats) | How the attacks are simulated and detected |
| [I. Execution](#i-how-to-run-the-project) | Commands, sample outputs, what success looks like |

Other docs: [SETUP.md](SETUP.md) (installation) · [CODE_WALKTHROUGH.md](CODE_WALKTHROUGH.md) (every file explained) · [GITHUB_GUIDE.md](GITHUB_GUIDE.md) (publishing, 7-day commit plan, proof checklist)

---

## A. Project explanation

### In simple language

Imagine a company's network as a busy airport. Thousands of "passengers" (network connections)
pass through every minute. Most are ordinary travellers. A few are troublemakers:

* someone **jamming the entrance** so no one else can get in → *Denial of Service (DoS)*
* someone **rattling every door handle** to see which is unlocked → *port scan / probe*
* someone **trying thousands of keys** on one door → *brute-force password attack*
* an employee **sneaking suitcases of documents** out at midnight → *data exfiltration*
* someone doing something **nobody has ever seen before** → *zero-day attack*

Security guards (SOC analysts) can't watch every passenger. So we train an **AI security camera**:

1. It studies recordings of past days where we know who was a troublemaker (**training**).
2. It learns what each type of troublemaker *behaves* like (**pattern recognition**).
3. It also learns what a *normal* passenger looks like, so anything weird stands out (**anomaly detection**).
4. When watching live, it raises an **alarm** with a priority level and tells the guard what to do (**alerting**).

### In technical language

AI-powered threat detection applies machine learning to security telemetry (network flows, logs,
endpoint events, transactions) to classify or score events as malicious. This project is a
**flow-based Network Intrusion Detection System (NIDS)** with a **hybrid detection engine**:

* a **supervised multi-class classifier** (Random Forest) trained on labelled flows to recognise
  known attack families (signature-free misuse detection), and
* an **unsupervised one-class anomaly detector** (Isolation Forest) fit only on benign traffic to
  flag statistical outliers (anomaly-based detection), covering novel/zero-day behaviour.

Outputs are post-processed into SOC artefacts: alerts with severity, MITRE ATT&CK technique,
explanation and recommended response; alerts are correlated into incidents per source entity.

### What problems does it solve?

| Problem | How AI helps |
|---|---|
| **Volume** - millions of events/day, humans can read a few hundred | Scores every event automatically (~20k events/s here) |
| **Unknown attacks** - signatures only catch known threats | Anomaly detection flags never-seen behaviour |
| **Alert fatigue** - SOCs drown in false positives | Confidence thresholds, severity, incident grouping |
| **Slow response** - attackers dwell for weeks | Real-time detection and recommended actions |
| **Evolving attackers** | Models are retrained on new data instead of rewriting rules by hand |

### Why is it important in today's AI-driven world?

* Attackers now use automation and AI to generate phishing, mutate malware and scan the internet
  in minutes - defence must be equally automated.
* Cloud, remote work and IoT exploded the attack surface; perimeter firewalls alone aren't enough.
* Regulations (RBI cybersecurity framework, GDPR, India's DPDP Act, PCI-DSS) require continuous monitoring.
* There's a global shortage of security analysts, so ML is used to triage and prioritise.

### How companies use these systems

| Use case | What is analysed | Typical ML | Example products |
|---|---|---|---|
| **Intrusion detection** | Network flows (NetFlow/IPFIX, Zeek logs) | Random Forest, gradient boosting, autoencoders | Darktrace, Vectra AI, Cisco Secure Network Analytics, ExtraHop |
| **Fraud detection** | Card / UPI transactions, logins | Gradient boosting + anomaly detection + graph ML | Bank in-house systems, FICO Falcon, Razorpay/Paytm risk engines |
| **Anomaly detection (UEBA)** | User logins, file access, VPN usage | Isolation Forest, clustering, sequence models | Splunk UBA, Microsoft Sentinel, Exabeam |
| **Malware detection** | File bytes, PE headers, API call sequences | CNNs/gradient boosting on static + dynamic features | CrowdStrike Falcon, Microsoft Defender, SentinelOne |
| **Network security monitoring** | All of the above in a SIEM | Correlation rules + ML scoring | Splunk ES, IBM QRadar, Elastic Security, Google Chronicle |

**Banks** - score every transaction in milliseconds; block or step-up authentication (OTP) for risky
ones; detect account takeover from unusual login location/device; monitor internal networks for
data exfiltration (mandated by regulators).

**IT services companies** (TCS, Infosys, Wipro, HCL...) - run **managed SOC** services for clients:
24×7 analysts watch SIEM dashboards where ML models pre-rank alerts. Freshers often start as
**L1 SOC analysts** triaging exactly the kind of alerts this project produces.

**Product companies** (Google, Microsoft, Amazon, Flipkart, Zomato) - detect bots, credential
stuffing on login pages, abuse of APIs, DDoS against their services, and insider data theft.

### The complete workflow

```
Data collection → Preprocessing → Feature engineering → Model training
      → Evaluation → Prediction → Alert generation → Visualisation / dashboard
```

| Stage | In industry | In this project |
|---|---|---|
| **Data collection** | Firewalls, routers (NetFlow), Zeek/Suricata sensors, SIEM | `simulator.py` generates flow records; or NSL-KDD |
| **Preprocessing** | Parsing, normalising, dedup, enrichment | `preprocessing.clean_data()` - dedupe, types, missing, invalid values |
| **Feature engineering** | Aggregations over time windows, ratios, encodings | `feature_engineering.py` - 9 security features + one-hot + scaling |
| **Detection model** | Supervised + unsupervised ensembles | Random Forest + Isolation Forest (+ Logistic Regression baseline) |
| **Training** | Historical labelled incidents | Day-1 traffic, stratified 75/25 split |
| **Prediction** | Streaming scoring | `detector.detect()` on Day-2 traffic; `simulate` command streams by hour |
| **Alert generation** | SIEM alerts, SOAR playbooks | Severity, MITRE ATT&CK, reason, recommended action, incidents |
| **Visualisation** | SOC dashboards (Splunk, Kibana) | 12 PNG charts + `outputs/soc_report.html` |

---

## B. Tech stack options

| | **Option A - Easiest** | **Option B - Intermediate** ✅ | **Option C - Advanced** |
|---|---|---|---|
| **Idea** | One notebook, one dataset, one model | Modular Python project, hybrid models, simulator, alerts, tests | Deep learning + streaming + deployed dashboard |
| **Tools** | Python, pandas, scikit-learn, matplotlib, Jupyter | + seaborn, joblib, pytest, argparse CLI, sklearn Pipelines | + TensorFlow/PyTorch, XGBoost, SHAP, Kafka, FastAPI, Streamlit, Docker, Elasticsearch |
| **Dataset** | NSL-KDD (CSV) | Simulated traffic **+** NSL-KDD | CICIDS2017 / UNSW-NB15 (GBs of PCAP-derived flows) |
| **Models** | Logistic Regression or Random Forest | Random Forest + Isolation Forest + LR baseline | Autoencoder, LSTM, XGBoost ensemble |
| **Difficulty** | ⭐ (2-3 days) | ⭐⭐⭐ (1-2 weeks) | ⭐⭐⭐⭐⭐ (1-2 months) |
| **Expected output** | Accuracy + confusion matrix in a notebook | CLI pipeline, 12 charts, SOC alerts, incidents, HTML report, tests | Live web dashboard with real-time alerts |
| **GPU needed?** | No | No | Helpful for deep learning |
| **GitHub impression** | "Followed a tutorial" | "Built an engineered system" | Impressive but risky to finish |

## C. Selected approach

**Option B** - it gives the best ratio of *proof of skill* to *risk of not finishing*:

* Runs on any laptop in about a minute, no GPU, no big downloads.
* Shows ML skill (3 models, proper metrics, imbalance handling) **and** security domain skill
  (attack fingerprints, MITRE ATT&CK, severity, incidents) **and** software engineering
  (modules, CLI, tests, docs) - the three things interviewers probe.
* The hybrid zero-day story is a memorable talking point in interviews.
* Easy to extend toward Option C later (see README "Future improvements").

---

## D. Architecture

### Block diagram

```
                         ┌────────────────────────────────────────────┐
                         │               INPUT DATA                    │
                         │  simulator.py (Day-1 train, Day-2 live)     │
                         │  or NSL-KDD (KDDTrain+ / KDDTest+)          │
                         │  one row = one network connection (flow)    │
                         └─────────────────────┬──────────────────────┘
                                               ▼
                         ┌────────────────────────────────────────────┐
                         │  PREPROCESSING  (preprocessing.py)          │
                         │  dedupe → types → fill missing → clip       │
                         │  split: X features | y label | meta (IP,ts) │
                         └─────────────────────┬──────────────────────┘
                                               ▼
                         ┌────────────────────────────────────────────┐
                         │  FEATURE ENGINEERING (feature_engineering)  │
                         │  + total_bytes, log bytes, bytes_ratio,     │
                         │    total_error_rate, has_failed_login,      │
                         │    zero_payload, srv_focus_ratio,           │
                         │    malformed_packet                         │
                         │  OneHotEncoder(protocol, service, flag)     │
                         │  StandardScaler(numeric)                    │
                         └───────────┬──────────────────┬─────────────┘
                                     ▼                  ▼
              ┌────────────────────────────┐  ┌───────────────────────────────┐
              │ RANDOM FOREST (supervised) │  │ ISOLATION FOREST (unsupervised)│
              │ 200 trees, class_weight=   │  │ 300 trees, fit on NORMAL only  │
              │ balanced → type + prob     │  │ → anomaly score; threshold =   │
              │                            │  │   99th pct of normal scores    │
              └──────────────┬─────────────┘  └───────────────┬───────────────┘
                             └──────────────┬─────────────────┘
                                            ▼
                         ┌────────────────────────────────────────────┐
                         │  DECISION ENGINE (detector.detect)          │
                         │  attack & conf ≥ 0.5 → KNOWN_ATTACK         │
                         │  else score ≥ threshold → ANOMALY           │
                         │  else → BENIGN ; then severity rules        │
                         └─────────────────────┬──────────────────────┘
                                               ▼
                ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐
                │ ALERTS            │→ │ INCIDENTS         │→ │ VISUALISATION / REPORT   │
                │ alerts.csv/json   │  │ incidents.csv     │  │ images/*.png             │
                │ MITRE, reason,    │  │ per (type, src_ip)│  │ outputs/soc_report.html  │
                │ action, severity  │  │                   │  │ outputs/metrics.json     │
                └──────────────────┘  └──────────────────┘  └─────────────────────────┘
```

### Module-wise explanation

| Module | Responsibility | Key design choice |
|---|---|---|
| `config.py` | All paths, thresholds, severity/MITRE maps | No magic numbers scattered in code |
| `simulator.py` | Generates realistic labelled traffic | Same feature names as NSL-KDD → code works on both |
| `data_loader.py` | Loads synthetic or NSL-KDD | Single `load_datasets()` entry point |
| `preprocessing.py` | Cleaning, X/y split | Meta columns (IP, time) never reach the model - avoids learning identifiers |
| `feature_engineering.py` | Domain features + encoding | Lives inside the sklearn Pipeline → identical at train & detect time |
| `models.py` | Builds/trains RF, LR, IF | IF trained on normal only; threshold from normal-score percentile |
| `evaluate.py` | Metrics | Reports FPR and per-class recall, not just accuracy |
| `detector.py` | Verdicts, severity, alerts, incidents | Hybrid rule combines both models |
| `visualize.py` | 12 charts | Fixed colour per threat type across all charts |
| `report.py` | HTML SOC report | Self-contained (images embedded) - one file to share |
| `main.py` | CLI orchestration | `generate / train / detect / simulate / all` |

### Data flow

1. `generate` writes `data/raw/train_traffic.csv` (Day 1, 27,100 rows) and `data/raw/live_traffic.csv` (Day 2, 13,650 rows incl. 100 zero-day).
2. `train` cleans Day 1 → `data/processed/train_clean.csv` → 75/25 stratified split → fits models on 75% → evaluates on 25% → saves `models/threat_detector.joblib` + `outputs/metrics.json` + charts 01-06.
3. `detect` loads the bundle → cleans Day 2 → scores every row → `outputs/predictions.csv` → alerts (`alerts.csv`, `alerts_sample.json`) → incidents (`incidents.csv`) → charts 07-12 → `soc_report.html`.
4. `simulate` does step 3 hour by hour, printing alerts as they "arrive".

---

## Implementation plan (10 phases)

### Phase 1 - Setup
* **What:** install Python 3.10+, create the folder structure and a virtual environment, install requirements, `git init`.
* **Why:** isolated, reproducible environment; anyone can clone and run.
* **Expected output:** `pip list` shows scikit-learn, pandas...; `python -c "import sklearn"` works.
* **Common mistakes:** installing into global Python; forgetting to activate venv; committing `venv/`.
* **Verify:** `where python` (Windows) / `which python` points inside `venv`.

### Phase 2 - Dataset loading
* **What:** `python main.py generate` (or `--dataset nsl-kdd`).
* **Why:** you need data before anything else; inspecting it reveals its shape and quirks.
* **Expected output:** two CSVs; console shows label counts (normal 20,000 / dos 4,000 / ...).
* **Common mistakes:** reading NSL-KDD without column names (it has no header row); wrong relative paths.
* **Verify:** `pd.read_csv(...).shape` is `(27100, 24)`; preview in the notebook looks sensible.

### Phase 3 - Data cleaning
* **What:** `clean_data()` - drop duplicates, coerce types, fill missing, clip negative/out-of-range values.
* **Why:** garbage in → garbage out; real logs always contain duplicates and broken rows.
* **Expected output:** `[clean] rows_in=27100, exact_duplicates_removed=0, missing_values_filled=0, rows_out=27100`.
* **Common mistakes:** filling missing values *before* the train/test split using statistics of the whole dataset (leakage); dropping all rows with any NaN.
* **Verify:** `df.isna().sum().sum() == 0`; `test_cleaning_handles_dirty_rows` passes.

### Phase 4 - Feature engineering
* **What:** add 9 domain features; one-hot encode protocol/service/flag; scale numerics.
* **Why:** models learn faster and generalise better from features that encode expert knowledge (e.g. upload/download ratio exposes exfiltration).
* **Expected output:** 55 model input columns after encoding (on the synthetic data).
* **Common mistakes:** fitting the scaler on the full dataset; `OneHotEncoder` crashing on unseen categories (fixed with `handle_unknown="ignore"`); using IP addresses as features (model memorises attackers instead of behaviour).
* **Verify:** no NaN/inf in engineered features (`test_engineered_features_have_no_nans`).

### Phase 5 - Model building
* **What:** train Logistic Regression (baseline), Random Forest (main), Isolation Forest (anomaly).
* **Why:** a baseline shows the main model genuinely adds value; the anomaly model covers unknown threats.
* **Expected output:** `[train] random_forest trained on 20,325 rows in ~6s`.
* **Common mistakes:** ignoring class imbalance (use `class_weight="balanced"`); training Isolation Forest on attack data too.
* **Verify:** `models/threat_detector.joblib` exists and loads.

### Phase 6 - Model evaluation
* **What:** accuracy, precision, recall, F1 (macro + per class), false-positive rate, confusion matrix, ROC-AUC for IF.
* **Why:** in security, a missed attack (FN) and a false alarm (FP) have very different costs; accuracy hides both.
* **Expected output:** RF accuracy 0.9945, macro-F1 0.993, FPR 0.00%; LR accuracy 0.985; IF ROC-AUC 0.985.
* **Common mistakes:** evaluating on training data; reporting only accuracy; claiming 100% (a red flag of leakage or a trivial dataset).
* **Verify:** test set is untouched during training; numbers in `outputs/metrics.json` match the console.

### Phase 7 - Threat detection logic
* **What:** combine models → verdict → severity → alerts → incidents.
* **Why:** analysts need actionable, prioritised alerts, not probability arrays.
* **Expected output:** 3,701 alerts grouped into 110 incidents on the live day.
* **Common mistakes:** alerting on every low-confidence prediction (alert storm); no explanation text.
* **Verify:** detection scorecard - attacks ≥ 98% alerted, zero-day 95%, normal ≈ 1%.

### Phase 8 - Visualisation
* **What:** 12 charts + HTML report.
* **Why:** charts are the fastest way for a recruiter/manager to see that it works.
* **Expected output:** `images/01_...png` … `images/12_...png`, `outputs/soc_report.html`.
* **Common mistakes:** unlabeled axes; inconsistent colours; linear scale hiding small classes (we use log scale where needed).
* **Verify:** open every PNG; timeline spikes line up with attack windows.

### Phase 9 - GitHub publishing
See [GITHUB_GUIDE.md](GITHUB_GUIDE.md).

### Phase 10 - Final output
* `python main.py all` runs clean from a fresh clone; `python -m pytest -q` → 7 passed.
* README has results table + screenshots; repo has topics, description, license.
* Record a 60-90 s demo video/GIF of `python main.py simulate`.

---

## H. Virtual simulation of cyber threats

### How the dataset represents real network traffic

Real sensors (Zeek, NetFlow, firewall logs) summarise each **connection** into one record:
who talked to whom, using which protocol/service, how long, how many bytes, how the TCP handshake
ended, and statistics about *recent* connections from the same host (last 2 seconds / last 100
connections). Our simulator emits exactly those fields:

| Field group | Columns | Real-world meaning |
|---|---|---|
| Basic | `duration, protocol_type, service, flag, src_bytes, dst_bytes` | One connection's summary. `flag` = TCP state: `SF` normal, `S0` SYN with no reply, `REJ` rejected, `RSTO` reset |
| Content | `wrong_fragment, urgent, num_failed_logins, logged_in` | Packet anomalies & login outcomes |
| Time-window traffic | `count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate` | Activity of this source in the last 2 s |
| Host-window traffic | `dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_serror_rate` | Activity toward this destination over the last 100 connections |
| Context (not model input) | `timestamp, src_ip, dst_ip` | Needed by analysts, excluded from training |

Normal traffic follows a **diurnal curve** (busy 9-18h), mostly internal IPs `10.0.x.x`, and contains
realistic "grey" traffic: ICMP pings, nightly backups (large uploads), busy-server bursts, password typos.

### How attacks are represented

| Attack | Real-world technique | Signature in the data |
|---|---|---|
| **DoS** (SYN flood) | Botnet sends SYNs, never completes handshake | `flag=S0`, `src_bytes≈0`, `count` 200-500, `serror_rate≈1`, 25 external IPs → 1 web server, 25-min burst |
| **Probe** (port scan, e.g. nmap) | One host touches many ports/services | 18 different services, `REJ` flags, `rerror_rate` high, `diff_srv_rate` high; 20% stealthy |
| **Brute force** (e.g. Hydra on SSH) | Rapid login attempts | `service∈{ssh,ftp,telnet}`, `num_failed_logins` 1-5, `logged_in=0`, high `same_srv_rate`; 20% low-and-slow |
| **Exfiltration** | Insider uploads data to external server | `src_bytes` MBs, long `duration`, 22:00-23:00, internal → external IP |
| **Zero-day** | Unknown exploit using malformed ICMP | `wrong_fragment>0`, `urgent>0`, ~1450-byte ICMP - **never shown to the classifier** |

Attack times are randomised per day so the model can't memorise "3 AM = attack". 2% of attack-labelled
flows are benign-looking (attacker's normal requests inside the attack window), mirroring how real
datasets are labelled.

### How the model detects suspicious behaviour

* **Random Forest** learns decision rules such as *"if serror_rate > 0.8 and count > 150 → dos"*
  across 200 trees and votes. Feature importance (chart 05) shows which signals matter.
* **Isolation Forest** randomly splits feature space; unusual points get isolated in very few splits →
  high anomaly score. Because it only learned *normal*, it doesn't need any attack examples.
* **Decision engine** trusts the classifier when it's confident about a known attack; otherwise, if
  the anomaly score exceeds the 99th percentile of normal traffic, it raises an `ANOMALY`.

### How alerts are generated

```
verdict → severity (base by type: exfiltration=CRITICAL, dos/brute_force=HIGH, probe/anomaly=MEDIUM;
          -1 level if confidence < 70%; anomaly → HIGH if score ≥ 1.15 × threshold)
        → alert record {alert_id, time, src→dst, service, threat_type, severity, confidence,
                         anomaly_score, MITRE ATT&CK, reason, recommended_action}
        → incidents: group by (threat_type, src_ip) with first/last seen, count, targets, bytes out
```

### Step-by-step simulation workflow

| Step | Command / action | What happens | Capture as proof |
|---|---|---|---|
| 1 | `python main.py generate` | Simulates Day 1 (27,100 flows) and Day 2 (13,650 flows incl. zero-day) | Screenshot of label counts + data preview |
| 2 | Open `notebooks/01_exploratory_data_analysis.ipynb` | Explore attack fingerprints | Screenshot of the fingerprint table |
| 3 | `python main.py train` | Clean → features → 3 models → metrics | Screenshot of metrics block; charts 01-06 |
| 4 | `python main.py detect` | Score Day 2, raise alerts, incidents, report | Screenshot of sample alerts + scorecard; charts 07-12 |
| 5 | `python main.py simulate` | Hour-by-hour live feed | **Screen recording / GIF** - your best demo asset |
| 6 | Open `outputs/soc_report.html` | SOC dashboard | Full-page screenshot |
| 7 | `python -m pytest -q` | 7 tests | Screenshot "7 passed" |
| 8 | Inspect `outputs/incidents.csv` | 110 incidents, exfiltration is INC-0001 (CRITICAL) | Screenshot in Excel |

### Outputs, graphs and anomalies to highlight

| File | Highlight |
|---|---|
| `images/07_attack_timeline.png` | Traffic spikes at 02:00 (DoS) and 06:00 (scan) line up exactly with alert bars |
| `images/12_live_anomaly_scores.png` | Green zero-day bars sit far right of the threshold while normal (blue) sits left |
| `images/10_anomaly_scatter_pca.png` | DoS and probe form separate clusters; anomalies (X) sit outside the grey normal cloud |
| `images/03_confusion_matrix_random_forest.png` | Strong diagonal; errors are attacks predicted as normal (the 2% benign-looking flows) |
| `images/11_detection_scorecard.png` | Attacks ≈ 98-99%, zero-day 95%, normal 1.1% |
| `outputs/incidents.csv` | 3,701 alerts → 110 incidents = 97% less noise for the analyst |

---

## I. How to run the project

```bash
python main.py all          # everything (≈1 minute)
```

Or step by step:

```bash
python main.py generate     # 1. create data
python main.py train        # 2. train + evaluate (creates models/threat_detector.joblib)
python main.py detect       # 3. predictions, alerts, incidents, report
python main.py simulate     # 4. real-time style replay (--delay 0.3 --show 3)
python -m pytest -q         # 5. tests
```

Testing a prediction yourself in Python:

```python
from src.detector import load_bundle, detect
from src.preprocessing import clean_data
from src.simulator import generate_traffic

bundle = load_bundle()
traffic = clean_data(generate_traffic(n_normal=500, seed=7, include_zero_day=True))
results = detect(traffic, bundle)
print(results[["timestamp", "src_ip", "label", "verdict", "threat_type", "severity"]].head(20))
```

### Sample output (training)

```
=== random_forest ===
  Accuracy            : 0.9945
  Precision (macro)   : 0.9985
  Recall (macro)      : 0.9873
  F1 score (macro)    : 0.9928
  Attack detection    : 97.92%  |  False positive rate: 0.00%

=== isolation_forest (unsupervised, never saw an attack label) ===
  roc_auc=0.9846, detection_rate_recall=0.8513, precision=0.9649, false_positive_rate=0.011
```

### Sample output (detection)

```
[detect] scored 13,650 connections in 0.6s (~22,000 connections/sec)
Verdicts: {'BENIGN': 9949, 'KNOWN_ATTACK': 3495, 'ANOMALY': 206}

Detection scorecard vs ground truth:
              connections  alerted  as_known_attack  as_anomaly  alert_rate
normal              10000      112                3         109      0.0112
dos                  2000     1968             1966           2      0.9840
probe                 800      786              786           0      0.9825
brute_force           600      591              591           0      0.9850
exfiltration          150      149              149           0      0.9933
anomaly               100       95                0          95      0.9500
```

### What successful detection looks like

* Every attack class alerted ≥ 98%, normal traffic alerted ≈ 1% (the false-alarm budget you chose with `ANOMALY_PERCENTILE`).
* The zero-day row shows `as_known_attack = 0` but `as_anomaly ≈ 95` - proof the hybrid design works.
* The exfiltration incident is ranked first (CRITICAL) even though it has fewer alerts than the DoS.
* Running twice gives identical numbers (fixed random seeds = reproducible science).

### Tuning knobs (in `src/config.py`)

| Setting | Effect |
|---|---|
| `ANOMALY_PERCENTILE` 99 → 99.5 | Fewer false alarms, may miss more zero-day |
| `CLASSIFIER_CONFIDENCE` 0.5 → 0.7 | Fewer but surer KNOWN_ATTACK alerts |
| `--rows 50000` | Bigger simulation |
