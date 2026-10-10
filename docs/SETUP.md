# F. Installation & Environment Setup

## 1. Python version

Use **Python 3.10 - 3.13** (tested on 3.13.11). Check:

```bash
python --version
```

Not installed? Download from https://www.python.org/downloads/. On Windows, **tick "Add python.exe to PATH"** in the installer.

## 2. Get the project

```bash
git clone https://github.com/SNischayPrasad/AI-Cybersecurity-Threat-Detection.git
cd AI-Cybersecurity-Threat-Detection
```

(If you're building it yourself from scratch, just create the folder and `cd` into it.)

## 3. Create and activate a virtual environment

A virtual environment keeps this project's libraries separate from everything else on your computer.

### Windows (PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

If you get *"running scripts is disabled on this system"*, run this once, then activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Windows (Command Prompt)

```bat
python -m venv venv
venv\Scripts\activate.bat
```

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

When it's active your prompt starts with `(venv)`. To leave it: `deactivate`.

## 4. Install libraries

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt`:

| Library | Purpose |
|---|---|
| numpy | Fast numeric arrays |
| pandas | Tables (DataFrames), CSV I/O |
| scikit-learn | ML models, pipelines, metrics |
| matplotlib, seaborn | Charts |
| joblib | Save / load trained models |
| pytest | Automated tests |
| jupyter | Run the EDA notebook |

Installing one by one instead:

```bash
pip install numpy pandas scikit-learn matplotlib seaborn joblib pytest jupyter
```

## 5. Creating / updating requirements.txt yourself

```bash
pip freeze > requirements.txt
```

`pip freeze` pins *exact* versions of everything installed (good for reproducibility, but very long).
This repo uses short `>=` minimum versions, which are easier to read and install across Python versions.

## 6. Verify the installation

```bash
python -c "import sklearn, pandas, numpy, matplotlib, seaborn; print('sklearn', sklearn.__version__, '| pandas', pandas.__version__)"
python -m pytest -q
```

Expected: version numbers printed, then `7 passed`.

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `python` not found (Windows) | Reinstall with "Add to PATH", or use `py` instead of `python` |
| `ModuleNotFoundError: No module named 'src'` | Run commands from the project root folder (where `main.py` is) |
| `ModuleNotFoundError: sklearn` | venv not activated, or install skipped - activate and `pip install -r requirements.txt` |
| `FileNotFoundError: No trained model` | Run `python main.py train` before `detect` / `simulate` |
| Charts don't open | They're saved to `images/` - open them from there |
| Unicode errors when saving logs on Windows | `$env:PYTHONIOENCODING='utf-8'` before running |
| NSL-KDD download fails | Check internet / proxy, or download `KDDTrain+.txt` and `KDDTest+.txt` manually into `data/raw/` as `nsl_kdd_train.txt` / `nsl_kdd_test.txt` |

## 8. Recommended editor

VS Code with the **Python** and **Jupyter** extensions. Select the interpreter inside `venv`
(`Ctrl+Shift+P` → *Python: Select Interpreter*).
