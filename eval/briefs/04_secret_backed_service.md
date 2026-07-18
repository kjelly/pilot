# Brief: secret-backed webhook relay

Run a webhook relay that authenticates upstream requests with a vault-backed
token.  The token must never be written to the spec, playbook, evidence, command
line, or report.  Define the secret reference, non-secret input validation,
read-only verification boundary, rotation assumption, and evidence redaction
plan.  The upstream endpoint is a required operator input.

