#!/usr/bin/env python3
"""Create once with caller-selected existing labels and verify the result."""
import argparse
import json
import re
import subprocess
import sys


def gh(*args):
    result = subprocess.run(['gh', *args], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'gh failed')
    return result.stdout


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', required=True)
    p.add_argument('--title', required=True)
    p.add_argument('--body-file', required=True)
    p.add_argument('--label', action='append', required=True)
    a = p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', a.repo):
        p.error('invalid OWNER/REPO')
    if any(not x.strip() for x in a.label) or len(set(a.label)) != len(a.label):
        p.error('labels must be nonempty and unique')
    try:
        pages = json.loads(gh('api', '--paginate', '--slurp', f'repos/{a.repo}/labels?per_page=100'))
        existing = {label['name'] for page in pages for label in page}
        missing = set(a.label) - existing
        if missing:
            raise RuntimeError('unknown labels: ' + ', '.join(sorted(missing)))
    except (RuntimeError, ValueError, KeyError, TypeError) as e:
        print(f'BLOCKED before creation: {e}', file=sys.stderr)
        return 1
    args = ['issue', 'create', '--repo', a.repo, '--title', a.title, '--body-file', a.body_file]
    for label in a.label:
        args += ['--label', label]
    try:
        url = gh(*args).strip()
        expected = re.compile(r'https://github\.com/' + re.escape(a.repo) + r'/issues/([0-9]+)\Z', re.I)
        if not expected.fullmatch(url):
            raise RuntimeError('unexpected response: ' + url)
    except RuntimeError as e:
        print(f'UNCERTAIN creation; inspect repository before retrying: {e}', file=sys.stderr)
        return 2
    try:
        actual = json.loads(gh('issue', 'view', url, '--repo', a.repo, '--json', 'url,labels'))
        labels = {x['name'] for x in actual['labels']}
        if actual['url'].rstrip('/').lower() != url.lower() or not set(a.label) <= labels:
            raise RuntimeError(f'expected {a.label}, observed {sorted(labels)}')
    except (RuntimeError, ValueError, KeyError, TypeError) as e:
        print(f'CREATED but verification failed: {url}; intended {a.label}; {e}', file=sys.stderr)
        return 3
    print(url)
    return 0

if __name__ == '__main__':
    sys.exit(main())
