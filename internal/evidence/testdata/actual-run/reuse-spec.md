# Controlled controller reuse fixture

## 1. Target

A disposable VM or topology whose rendered inventory contains the selected hosts.
The effective managed file must contain the declared acceptance value.

## 2. Checklist

| ID | Category | Check | Expected | Command |
| --- | --- | --- | --- | --- |
| C1 | file | Effective managed file content | pr225-reuse-v1 | `cat /etc/pilot-pr225-reuse.conf` |
