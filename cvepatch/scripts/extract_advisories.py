#!/usr/bin/env python3
"""One-time: CVE list zip -> advisories.jsonl (agent-facing advisory per CVE).

  python scripts/extract_advisories.py --cve-zip <cvelist.zip.zip> \
      --rows <cve_triage.jsonl> --out <advisories.jsonl>

Only CVEs with open-source evidence in the triage rows are kept.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from triage import iter_zip_json, open_cve_zip  # noqa: E402

from cvepatch.core.ingestion.advisory import advisory_from_record  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve-zip", type=Path, required=True)
    ap.add_argument("--rows", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    want = set()
    with a.rows.open() as fh:
        for ln in fh:
            r = json.loads(ln)
            if r.get("open_source"):
                want.add(r["cve"])
    n = 0
    with a.out.open("w") as out:
        for _name, rec in iter_zip_json(open_cve_zip(a.cve_zip)):
            if not isinstance(rec, dict):
                continue
            cve = (rec.get("cveMetadata") or {}).get("cveId")
            if cve not in want:
                continue
            adv = advisory_from_record(rec)
            if adv:
                out.write(json.dumps(adv) + "\n")
                n += 1
    print(f"wrote {n} advisories (of {len(want)} open-source CVEs) to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
