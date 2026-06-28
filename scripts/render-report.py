#!/usr/bin/env python3
"""render-report.py — NDJSON → markdown verification report

Usage:
    bash scripts/verify-<host>.sh > /tmp/verify.ndjson
    python3 scripts/render-report.py < /tmp/verify.ndjson > report.md

Output sections:
    - header with timestamp and counts
    - verdict (PASS / FAIL)
    - summary table
    - failures-only section (if any)
"""
import json
import sys
import datetime

rows = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        rows.append(json.loads(line))
    except json.JSONDecodeError as e:
        print(f"# WARN: malformed line skipped: {e}", file=sys.stderr)

total = len(rows)
passed = sum(1 for r in rows if r.get("status") == "pass")
failed = sum(1 for r in rows if r.get("status") == "fail")
skipped = sum(1 for r in rows if r.get("status") == "skip")
verdict = "PASS" if failed == 0 else "FAIL"

print("# Verification Report")
print()
ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
print(f'- generated: {ts}')
print(f"- total: {total}  pass: {passed}  fail: {failed}  skip: {skipped}")
print(f"- verdict: **{verdict}**")
print()
print("| ID | Status | Detail |")
print("|----|--------|--------|")

# 為了可讀性：fail 先列、其餘按 ID 排
fail_rows = [r for r in rows if r.get("status") == "fail"]
other_rows = [r for r in rows if r.get("status") != "fail"]
for r in fail_rows + sorted(other_rows, key=lambda x: x.get("id", "")):
    rid = r.get("id", "?")
    st = r.get("status", "?")
    det = r.get("detail", "")
    print(f"| {rid} | {st} | {det} |")

if failed > 0:
    print()
    print("## Failures")
    print()
    for r in fail_rows:
        print(f"- **{r.get('id')}**: {r.get('detail')}")

sys.exit(0 if verdict == "PASS" else 1)
