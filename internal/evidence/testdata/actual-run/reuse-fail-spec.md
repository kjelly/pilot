# Intentional verification failure control

## 1. Target

A disposable VM or topology whose rendered inventory contains the selected hosts.
The effective managed file must contain the declared acceptance value.

## 2. Checklist

| ID | Category | Check | Expected | Command |
| --- | --- | --- | --- | --- |
| C1 | file | Effective managed file content | pr225-reuse-intentionally-wrong | `cat /etc/pilot-pr225-reuse.conf` |
