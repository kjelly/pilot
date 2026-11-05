# Captured Wazuh real alert

Captured 2026-11-03 from the official Wazuh manager 4.14.1 container on a
disposable Ubuntu 24.04 target, baseline revision
`613c36162bc5cfbeac929c5b4224ec9689a54f3b`. The controller appended a realistic
sshd failure to the already monitored `/var/ossec/logs/active-responses.log`,
then read the resulting real `alerts/alerts.json` record. This was not
wazuh-logtest output or a fabricated positive record.

The JSON schema, rule fields, timestamp, agent and manager values are preserved.
Sanitization replaces the disposable hostname, source IP (RFC5737 documentation
address), and synthetic username/nonce. Negative tests derive missing-field,
wrong-nonce, stale-challenge, future-challenge and absent-output cases from this
record. Raw stdout and stderr are retained separately by the Issue #211 evidence
controller. The sole stderr diagnostic was an SSH first-connection known-host
warning; no Wazuh parse diagnostic was present.
