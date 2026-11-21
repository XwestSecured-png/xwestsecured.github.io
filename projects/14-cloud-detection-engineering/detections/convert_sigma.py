#!/usr/bin/env python3
"""Convert the exported Sigma rules to Splunk SPL with pySigma (optional dependency).

    pip install pysigma pysigma-backend-splunk
    python3 detections/convert_sigma.py sigma/ --out reports/splunk_queries.md
For Microsoft Sentinel (KQL) or Elastic, swap in pysigma-backend-kusto or pysigma-backend-elasticsearch.
"""
import argparse
from pathlib import Path

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

ap = argparse.ArgumentParser(); ap.add_argument("sigma_dir", type=Path); ap.add_argument("--out", type=Path, default=Path("reports/splunk_queries.md"))
a = ap.parse_args()
md = ["# Splunk SPL generated from the Sigma rules (pySigma)", "",
      "Field names follow the raw CloudTrail / Entra ID JSON. Add a field-mapping pipeline for your add-on (for example Splunk_TA_aws).", ""]
for f in sorted(a.sigma_dir.glob("*.yml")):
    col = SigmaCollection.from_yaml(f.read_text())
    md += [f"## {col.rules[0].title}", "", "```spl", "\n".join(SplunkBackend().convert(col)).strip(), "```", ""]
a.out.write_text("\n".join(md)); print(f"wrote {a.out}")
