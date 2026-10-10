# GitHub Guide - publishing, commit plan & proof checklist

Covers sections **J** (GitHub upload strategy), **L** (7-day commit plan), **M** (proof checklist)
and **13** (screenshots / demo assets).

---

## J. GitHub upload strategy

### 1. Repo identity

| Item | Recommendation |
|---|---|
| **Repo name** | `AI-Cybersecurity-Threat-Detection` (alternatives: `hybrid-ml-intrusion-detection`, `ai-soc-threat-detector`) |
| **Description** (≤ 350 chars) | `Hybrid ML network intrusion detection system: Random Forest for known attacks + Isolation Forest for zero-day anomalies. Simulates DoS, port scans, brute force & data exfiltration, raises SOC alerts with MITRE ATT&CK mapping. Python, scikit-learn, pandas.` |
| **Topics / tags** | `cybersecurity` `machine-learning` `intrusion-detection` `anomaly-detection` `threat-detection` `network-security` `soc` `scikit-learn` `random-forest` `isolation-forest` `nsl-kdd` `python` `data-science` `mitre-attack` |
| **Website field** | Link to a demo video (YouTube unlisted / LinkedIn post) once you have one |
| **License** | MIT (already in repo - replace `<YOUR NAME>`) |

### 2. Organise files before the first push

* Replace placeholders: `<YOUR NAME>` in `LICENSE`; `<Your Name>`, `<your-username>`, LinkedIn, email in `README.md`.
* Run `python main.py all` and `python -m pytest -q` - everything must pass on your machine.
* Check `.gitignore` is working - these must **not** be committed: `venv/`, `data/raw/*.csv`,
  `models/*.joblib` (12 MB), `outputs/predictions.csv`, `outputs/alerts.csv`.
* These **should** be committed as proof: `images/*.png`, `outputs/metrics.json`,
  `outputs/incidents.csv`, `outputs/alerts_sample.json`, `outputs/soc_report.html`,
  `outputs/training_log.txt`, the executed notebook.

### 3. Create the repository on GitHub

1. Go to https://github.com/new
2. Repository name: `AI-Cybersecurity-Threat-Detection`
3. Description: (from the table above)
4. **Public**
5. **Do not** tick "Add a README", ".gitignore" or "license" (you already have them - ticking causes a merge conflict on first push)
6. Click **Create repository**

### 4. Push the code (first time)

One-time Git identity setup (use the email linked to your GitHub account):

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

From inside the project folder:

```bash
git init
git branch -M main
git add .
git status
git commit -m "Initial commit: project structure and setup"
git remote add origin https://github.com/<your-username>/AI-Cybersecurity-Threat-Detection.git
git push -u origin main
```

`git status` before committing is your safety check - make sure no `venv/` or huge CSVs are listed.
GitHub asks you to sign in via the browser the first time (or use a Personal Access Token as password).

### 5. Everyday workflow after that

```bash
git add <files>                 # or: git add .
git commit -m "feat: add isolation forest anomaly detector"
git push
```

### 6. Writing good commit messages

Use the **Conventional Commits** style - recruiters and engineers recognise it:

| Prefix | Use for | Example |
|---|---|---|
| `feat:` | new functionality | `feat: add brute-force attack simulation` |
| `fix:` | bug fix | `fix: handle unseen service values in encoder` |
| `docs:` | documentation | `docs: add architecture diagram to README` |
| `test:` | tests | `test: add zero-day detection test` |
| `refactor:` | restructure, no behaviour change | `refactor: move thresholds into config.py` |
| `chore:` | setup, deps | `chore: add requirements.txt and .gitignore` |

Rules: present tense, ≤ 72 characters, one logical change per commit, **never** "update", "final", "asdf".

### 7. Uploading images & videos

* **Images** - already in `images/`, referenced in README with relative paths:
  `![Attack timeline](images/07_attack_timeline.png)` - they render automatically on GitHub.
* **Demo GIF** - record `python main.py simulate` with [ScreenToGif](https://www.screentogif.com/) (Windows) or [Kap](https://getkap.co/) (Mac).
  Keep it < 10 MB, save as `images/demo.gif`, and add near the top of the README: `![Demo](images/demo.gif)`.
* **Video (MP4)** - edit the README on github.com, drag-and-drop the MP4 into the editor
  (≤ 10 MB on free accounts). GitHub uploads it and inserts a link that plays inline.
  Longer videos → YouTube (unlisted) and link it.

### 8. Make it look professional

- [ ] README has badges, a one-line pitch, results table and screenshots **above the fold**
- [ ] About section: description + topics + website link filled in
- [ ] **Pin** the repo on your GitHub profile (Profile → Customize your pins)
- [ ] Create a **Release**: Releases → "Create a new release" → tag `v1.0.0` → title "v1.0 - Hybrid threat detection" → attach `soc_report.html`
- [ ] Optional: GitHub Actions workflow that runs `pytest` on every push → green ✔ badge
- [ ] Profile README (`<username>/<username>` repo) linking to this project
- [ ] Post on LinkedIn: the GIF + 3 bullet results + repo link

Optional CI file - `.github/workflows/tests.yml`:

```yaml
name: tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python -m pytest -q
```

---

## L. Seven-day commit plan (proof of consistent work)

> Build it genuinely day by day: type the code, run it, break it, fix it. Interviewers *will*
> ask "why did you choose X?" - the daily build is what lets you answer. A green contribution
> streak with meaningful commits is far stronger than one giant "upload project" commit.

| Day | Work | Files to commit | Commit message(s) | Proof to capture |
|---|---|---|---|---|
| **1 - Setup** | Install Python, venv, create structure, README skeleton | `.gitignore`, `requirements.txt`, `LICENSE`, `README.md` (title + overview), `src/__init__.py`, `src/config.py`, empty folders with `.gitkeep` | `chore: initialise project structure and environment`<br>`docs: add project overview to README` | `pip list` / pytest version screenshot; empty repo on GitHub |
| **2 - Dataset** | Write simulator & loader, generate data, start EDA notebook | `src/simulator.py`, `src/data_loader.py`, `notebooks/01_exploratory_data_analysis.ipynb` | `feat: add network traffic simulator with 5 attack types`<br>`feat: add NSL-KDD dataset loader`<br>`docs: add exploratory data analysis notebook` | `01_dataset_preview.png` (console preview + label counts), notebook fingerprint table |
| **3 - Preprocessing** | Cleaning + feature engineering | `src/preprocessing.py`, `src/feature_engineering.py` | `feat: add data cleaning pipeline`<br>`feat: engineer security features (bytes ratio, error rates)` | `02_preprocessing_output.png` (`[clean]` line), engineered feature list |
| **4 - Model** | Train RF, LR, IF; save bundle | `src/models.py`, `src/detector.py` (save/load), `main.py` (generate/train) | `feat: train random forest and logistic regression classifiers`<br>`feat: add isolation forest anomaly detector` | `03_training_logs.png` |
| **5 - Evaluation** | Metrics, confusion matrix, tests | `src/evaluate.py`, `tests/test_pipeline.py`, `outputs/metrics.json` | `feat: add evaluation metrics (precision, recall, F1, FPR)`<br>`test: add pipeline and detection tests` | `04_evaluation_metrics.png`, `05_pytest_passed.png`, confusion matrix |
| **6 - Visualisation & detection** | Alerts, incidents, charts, simulate mode, HTML report | `src/detector.py` (alerts), `src/visualize.py`, `src/report.py`, `main.py` (detect/simulate), `images/*.png` | `feat: generate SOC alerts with severity and MITRE ATT&CK mapping`<br>`feat: add 24h attack timeline and detection charts`<br>`feat: add real-time simulation mode and HTML report` | timeline, scorecard, PCA charts, `06_alerts_console.png`, demo GIF |
| **7 - Final upload** | Polish README, docs, release, LinkedIn | `README.md`, `docs/*.md`, `outputs/*` proof files, `images/demo.gif` | `docs: add results, screenshots and architecture`<br>`docs: add setup, code walkthrough and GitHub guides`<br>`chore: release v1.0.0` | `08_github_repo_preview.png`, release page, LinkedIn post |

---

## 13. Screenshots / outputs / demo assets

### What the code generates automatically (`images/`)

| File | Shows |
|---|---|
| `01_class_distribution.png` | Dataset balance |
| `02_feature_correlation.png` | Correlation heatmap |
| `03_confusion_matrix_random_forest.png` | Per-class accuracy & errors |
| `04_model_comparison.png` | LR vs RF vs IF |
| `05_feature_importance.png` | Explainability |
| `06_anomaly_score_distribution.png` | IF scores on test set + threshold |
| `07_attack_timeline.png` | 24 h traffic vs alerts |
| `08_alerts_by_severity.png` | Alert triage view |
| `09_top_attacker_ips.png` | Top suspicious sources |
| `10_anomaly_scatter_pca.png` | Clusters in 2-D |
| `11_detection_scorecard.png` | Detection rate per true class |
| `12_live_anomaly_scores.png` | Zero-day separation |

### What YOU capture manually (save in `images/screenshots/`)

| # | File name | How to capture |
|---|---|---|
| 1 | `01_dataset_preview.png` | Terminal after `python main.py generate` (label counts + preview) |
| 2 | `02_preprocessing_output.png` | `[clean] ...` line and `[split]` line from `train` |
| 3 | `03_training_logs.png` | `[train]` lines with timings |
| 4 | `04_evaluation_metrics.png` | The `=== random_forest ===` block + per-class report |
| 5 | `05_pytest_passed.png` | `python -m pytest -q` → `7 passed` |
| 6 | `06_alerts_console.png` | Sample alerts + scorecard from `detect` |
| 7 | `07_soc_report.png` | Full-page browser screenshot of `outputs/soc_report.html` |
| 8 | `08_github_repo_preview.png` | Your repo home page with README rendered |
| 9 | `demo.gif` (in `images/`) | 30-60 s recording of `python main.py simulate` |

Windows: `Win + Shift + S` for screenshots. Mac: `Cmd + Shift + 4`. Use a dark terminal theme with
a large font (16-18 pt) so text is readable on GitHub.

### Showing them in the README

```markdown
## 🖼️ Screenshots
| Training | Detection |
|---|---|
| ![Training](images/screenshots/04_evaluation_metrics.png) | ![Alerts](images/screenshots/06_alerts_console.png) |

![Demo](images/demo.gif)
```

---

## M. Final proof checklist

**Code & reproducibility**
- [ ] `python main.py all` runs from a fresh clone without errors
- [ ] `python -m pytest -q` → 7 passed
- [ ] Same results on re-run (fixed seeds)
- [ ] No secrets, personal data, `venv/` or large files committed

**Evidence in repo**
- [ ] 12 auto-generated charts in `images/`
- [ ] 8 manual screenshots in `images/screenshots/`
- [ ] `outputs/metrics.json`, `incidents.csv`, `alerts_sample.json`, `soc_report.html`, `training_log.txt`
- [ ] Executed notebook with visible outputs
- [ ] Demo GIF/video

**Presentation**
- [ ] README: overview, problem, industry relevance, stack, architecture, dataset, install, run, results, screenshots, learning outcomes
- [ ] Description, topics, license, pinned on profile, v1.0.0 release
- [ ] ≥ 12 meaningful commits across ≥ 7 days
- [ ] LinkedIn post + resume bullet

**Resume bullet (copy-paste and adapt)**

> **AI-Powered Cybersecurity Threat Detection System** | Python, scikit-learn, pandas
> • Built a hybrid network intrusion detection system (Random Forest + Isolation Forest) that detected 98%+ of simulated DoS, port-scan, brute-force and exfiltration attacks with 0% false positives on held-out data, and 95% of an unseen zero-day attack.
> • Designed a traffic simulator and SOC alerting pipeline with severity scoring, MITRE ATT&CK mapping and incident grouping that reduced 3,701 alerts to 110 incidents.

**Interview questions to prepare**
1. Why not just use accuracy? (imbalance; FP vs FN cost)
2. How does Isolation Forest work, and why train it on normal traffic only?
3. How did you avoid data leakage? (split before fitting, Pipeline, IPs excluded)
4. Why are your results so high, and how would they hold on real traffic? (simulated data; NSL-KDD option; label noise; future work on CICIDS2017)
5. How would you deploy this in a real SOC? (stream ingestion, retraining, SIEM integration, analyst feedback loop)
