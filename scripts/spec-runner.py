#!/usr/bin/env python3
"""spec-runner.py — Directly execute verification markdown specs and output NDJSON.

Usage:
    python3 scripts/spec-runner.py docs/verification/bastion.md > /tmp/verify.ndjson
    python3 scripts/render-report.py < /tmp/verify.ndjson > report.md
"""
import sys
import os
import re
import subprocess
import json

def parse_spec(filepath):
    in_checklist = False
    headers = []
    rows = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith('## 2. Checklist'):
                in_checklist = True
                continue
            if in_checklist and line.startswith('##'):
                in_checklist = False
                continue
            if in_checklist:
                if line.startswith('|') and not line.startswith('|---') and not line.startswith('| ---'):
                    parts = [p.strip() for p in line.split('|')[1:-1]]
                    if not headers:
                        headers = [p.lower() for p in parts]
                    else:
                        rows.append(dict(zip(headers, parts)))
    return rows

def run_check(row):
    rid = row.get('id', '?')
    command = row.get('command', '').strip('` ')
    expected = row.get('expected', '').strip('` ')
    
    if not command:
        return {"id": rid, "status": "skip", "detail": "No command provided"}
        
    try:
        # Run command via shell
        res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        stdout = res.stdout.strip()
        stderr = res.stderr.strip()
        exit_code = res.returncode
        
        # 1. Check if expected is present / absent based on exit code
        if expected.lower() == 'present':
            if exit_code == 0:
                return {"id": rid, "status": "pass", "detail": f"present (exit_code=0). stdout: {stdout}"}
            else:
                return {"id": rid, "status": "fail", "detail": f"absent (exit_code={exit_code}). stderr: {stderr}"}
                
        elif expected.lower() in ('absent', 'missing'):
            if exit_code != 0:
                return {"id": rid, "status": "pass", "detail": f"absent/missing (exit_code={exit_code}). stderr: {stderr}"}
            else:
                return {"id": rid, "status": "fail", "detail": f"present (exit_code=0). stdout: {stdout}"}
                
        # 2. Regex match
        is_regex = False
        if expected.startswith('^') or expected.endswith('$') or '\\s' in expected or '\\d' in expected or '|' in expected:
            is_regex = True
            
        if is_regex:
            try:
                rx = re.compile(expected)
                # Combine stdout and stderr for regex validation
                combined = (stdout + "\n" + stderr).strip()
                if rx.search(combined):
                    return {"id": rid, "status": "pass", "detail": f"regex matched: {expected}"}
                else:
                    return {"id": rid, "status": "fail", "detail": f"got={combined} want_regex={expected}"}
            except re.error:
                pass # fallback to substring if regex compilation fails
                
        # 3. Substring / Exact match
        # Clean expected quotes
        clean_expected = expected
        if expected.startswith('"') and expected.endswith('"'):
            clean_expected = expected[1:-1]
        elif expected.startswith("'") and expected.endswith("'"):
            clean_expected = expected[1:-1]
            
        if clean_expected in stdout or clean_expected in stderr:
            return {"id": rid, "status": "pass", "detail": f"matched expected value: {expected}"}
        else:
            combined = (stdout + "\n" + stderr).strip()
            return {"id": rid, "status": "fail", "detail": f"got={combined} want={expected}"}
            
    except subprocess.TimeoutExpired:
        return {"id": rid, "status": "fail", "detail": "Command timed out (15s)"}
    except Exception as e:
        return {"id": rid, "status": "fail", "detail": f"Error executing command: {str(e)}"}

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 spec-runner.py <spec-markdown-file>", file=sys.stderr)
        sys.exit(1)
        
    spec_file = sys.argv[1]
    if not os.path.exists(spec_file):
        print(f"Error: spec file not found: {spec_file}", file=sys.stderr)
        sys.exit(1)
        
    rows = parse_spec(spec_file)
    if not rows:
        print(f"Warning: no checklist table found under '## 2. Checklist' in {spec_file}", file=sys.stderr)
        sys.exit(0)
        
    for r in rows:
        # Ignore table header templates or rows without a proper ID
        rid = r.get('id', '')
        if rid.startswith('C') and rid[1:].isdigit():
            result = run_check(r)
            print(json.dumps(result))
            
if __name__ == '__main__':
    main()
