"""
report.py - Build a single self-contained HTML "SOC dashboard" report.

Open outputs/soc_report.html in any browser. All charts are embedded,
so you can attach this one file anywhere as proof of the results.
"""

from __future__ import annotations

import base64
import html

import pandas as pd

from src import config


def _img(name: str) -> str:
    path = config.IMAGES_DIR / name
    if not path.exists():
        return ""
    data = base64.b64encode(path.read_bytes()).decode()
    return f'<figure><img src="data:image/png;base64,{data}" alt="{name}"><figcaption>{name}</figcaption></figure>'


def _table(df: pd.DataFrame, max_rows: int = 15) -> str:
    return df.head(max_rows).to_html(index=False, border=0, classes="tbl", escape=True)


def build_report(metrics: dict, alerts: pd.DataFrame, incidents: pd.DataFrame,
                 scorecard: pd.DataFrame, total_connections: int) -> None:
    rf = metrics["models"]["random_forest"]
    sev_counts = alerts["severity"].value_counts().reindex(config.SEVERITY_ORDER[::-1]).fillna(0).astype(int)
    tiles = "".join(
        f'<div class="tile"><div class="v">{v}</div><div class="k">{html.escape(k)}</div></div>'
        for k, v in [
            ("Connections analysed", f"{total_connections:,}"),
            ("Alerts raised", f"{len(alerts):,}"),
            ("Incidents", f"{len(incidents):,}"),
            ("Critical / High", f"{sev_counts.get('CRITICAL', 0) + sev_counts.get('HIGH', 0):,}"),
            ("RF test F1 (macro)", f"{rf['f1_macro']:.3f}"),
            ("RF false-positive rate", f"{rf['binary']['false_positive_rate']:.2%}"),
        ])

    alert_cols = ["alert_id", "timestamp", "severity", "threat_type", "src_ip", "dst_ip", "service", "reason"]
    top_alerts = alerts.sort_values("severity", key=lambda s: s.map(
        {s_: i for i, s_ in enumerate(config.SEVERITY_ORDER)}), ascending=False)[alert_cols]

    images = "".join(_img(p.name) for p in sorted(config.IMAGES_DIR.glob("*.png")))

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Threat Detection Report</title>
<style>
 :root {{ --bg:#0f172a; --card:#111c33; --fg:#e2e8f0; --muted:#94a3b8; --accent:#f97316; }}
 body {{ margin:0; font-family:Segoe UI,Roboto,Arial,sans-serif; background:var(--bg); color:var(--fg); }}
 main {{ max-width:1200px; margin:auto; padding:24px 16px; }}
 h1 {{ margin:0 0 4px; }} h2 {{ margin-top:36px; border-bottom:1px solid #334155; padding-bottom:6px; }}
 .muted {{ color:var(--muted); }}
 .tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-top:18px; }}
 .tile {{ background:var(--card); border-radius:10px; padding:14px; border-left:4px solid var(--accent); }}
 .tile .v {{ font-size:1.6rem; font-weight:700; }} .tile .k {{ color:var(--muted); font-size:.85rem; }}
 .tbl {{ width:100%; border-collapse:collapse; font-size:.82rem; background:var(--card); }}
 .tbl th, .tbl td {{ padding:6px 8px; border-bottom:1px solid #1e293b; text-align:left; }}
 .scroll {{ overflow-x:auto; }}
 figure {{ background:#fff; border-radius:10px; padding:8px; margin:16px 0; }}
 figure img {{ width:100%; height:auto; }} figcaption {{ color:#333; font-size:.8rem; text-align:center; }}
</style></head><body><main>
<h1>AI-Powered Cybersecurity Threat Detection - SOC Report</h1>
<div class="muted">Hybrid detection: Random Forest (known attacks) + Isolation Forest (zero-day anomalies)</div>
<div class="tiles">{tiles}</div>
<h2>Incidents (alerts grouped by attacker)</h2><div class="scroll">{_table(incidents)}</div>
<h2>Highest-priority alerts</h2><div class="scroll">{_table(top_alerts)}</div>
<h2>Detection scorecard (simulation ground truth)</h2><div class="scroll">{_table(scorecard.reset_index(), 20)}</div>
<h2>Charts</h2>{images}
</main></body></html>"""

    out = config.OUTPUTS_DIR / "soc_report.html"
    out.write_text(page, encoding="utf-8")
    print(f"[save] HTML report -> {out.relative_to(config.ROOT_DIR)}")
