"""Show the cleaning + feature-engineering stage on its own.

    python scripts/preprocess_demo.py
"""
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # project root
import pandas as pd

from src.data_loader import load_datasets
from src.feature_engineering import add_engineered_features
from src.models import _make_pipeline
from src.preprocessing import clean_data, split_features_labels

train, _ = load_datasets("synthetic")
print(f"[clean] raw data: {train.shape[0]:,} rows x {train.shape[1]} columns")
df = clean_data(train)
X, y = split_features_labels(df)
print(f"[clean] model input: {X.shape[1]} raw features (timestamp / IPs removed), label = '{y.name}'")
Xf = add_engineered_features(X)
new = [c for c in Xf.columns if c not in X.columns]
print(f"[engineer] {len(new)} new security features: {', '.join(new)}")
print()
cols = ["src_bytes", "dst_bytes", "bytes_ratio", "total_error_rate", "has_failed_login", "zero_payload"]
sample = pd.concat([Xf[cols], y], axis=1).groupby("label").head(1).set_index("label")
print("One example row per traffic type (engineered features):")
print(sample.round(2).to_string())
print()
pipe = _make_pipeline(X, None)
encoded = pipe.named_steps["preprocess"].fit_transform(pipe.named_steps["features"].transform(X))
print(f"[encode] one-hot (protocol, service, flag) + standard scaling -> {encoded.shape[1]} model inputs")
print(f"[encode] missing values after preprocessing: {int(pd.isna(encoded).sum())}")
