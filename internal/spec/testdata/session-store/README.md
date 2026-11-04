Native Ubuntu 24.04 systemctl field captures, 2026-11-03, Issue #77.

The active capture is from `systemctl show ssh.service --property=LoadState --property=ActiveState --property=MainPID` on the disposable `i77-host`; exit 0.
The absent capture is from the same query for `pilot-session-store.service` before installation; exit 0.
Raw controller artifacts: `/tmp/issue-to-pr-77/systemctl-active-ssh.txt` and `systemctl-absent.txt`. The SSH known-host warning (stderr) is excluded here; stdout key/value lines are preserved.

The local TLS harness substitutes the numeric MainPID with its actual process PID and may replace ActiveState to model faults. This proves parser/ownership/TLS behavior with a real socket, not native session-store systemd readiness. Root's separate VM evidence covers that boundary.
