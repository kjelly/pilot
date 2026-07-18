#!/usr/bin/env python3
"""Fail if any tracked YAML file has a duplicate key in the same mapping.

PyYAML's default loader silently keeps the LAST value of a duplicate key and
drops the rest — no warning, no error. That already bit this repo once:
playbooks/apply/freeipa-identity.roster.example.yaml had a `devops-sudo` sudo
rule with two `groups:` keys, and the first (`[sysops]`) was silently
discarded, leaving the rule scoped to only the second group. `pilot edit`
explicitly refuses to edit this class of nested-structure roster YAML (it
tells the user to reach for a text editor instead), so this is the one
class of file with zero tooling safety net against exactly this mistake —
hence a standalone check rather than relying on ansible-lint (which doesn't
check this) or `pilot edit` (which doesn't touch these files at all).
"""

import subprocess
import sys

import yaml


class DuplicateKeyError(ValueError):
    pass


class DuplicateKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise DuplicateKeyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def tracked_yaml_files():
    out = subprocess.run(
        ["git", "ls-files", "*.yml", "*.yaml"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [f for f in out.splitlines() if f]


def main():
    failures = []
    for path in tracked_yaml_files():
        try:
            with open(path, encoding="utf-8") as f:
                for doc in yaml.load_all(f, Loader=DuplicateKeyLoader):
                    pass
        except FileNotFoundError:
            # Tracked in the index but gone from disk — a deleted-but-unstaged
            # file, a normal dev state. Nothing on disk to check.
            continue
        except DuplicateKeyError as e:
            failures.append(f"{path}: {e}")
        except yaml.YAMLError:
            # Not this check's job — --syntax-check / ansible-lint catch
            # genuinely malformed YAML (e.g. Jinja-only fragments).
            continue

    if failures:
        print("Duplicate YAML mapping keys found (silently drops the earlier value):")
        for f in failures:
            print(f"  {f}")
        return 1

    print(f"✓ no duplicate YAML keys ({len(tracked_yaml_files())} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
