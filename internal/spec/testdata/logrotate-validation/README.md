# Logrotate validation captures

Captured on 2026-10-21 with the real local logrotate 3.22.0 binary and an extracted
Ubuntu logrotate 3.21.0 binary. Each capture ran with `LC_ALL=C`, debug mode and
`-s /dev/null`, against a real temporary policy containing `daily`, `rotate 14`,
and `missingok`; the negative policy additionally contained `bogusoption`.

All four commands returned **0**, despite the unknown-option diagnostic:
3.21 calls it `error:`, while 3.22 calls it `warning:` and ignores the line.
The stdout files are empty; diagnostics are on stderr. Only paths are sanitized:
the candidate file is `POLICY_PATH` and its log directory is `LOG_ROOT`.

The replay test substitutes only the candidate path, exercises the unchanged
production validator, and checks that diagnostics about another file do not
reject the candidate. Live tests separately run the installed binary and the
Ansible copy/lineinfile validate lifecycle.
