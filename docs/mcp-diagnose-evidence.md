# MCP diagnosis evidence

Latest verification: [2026-10-21 candidate 84c3291](evidence/mcp-diagnose-evidence/2026-10-21-84c3291.md).
Complete local normal/race suites and all four candidate CI jobs passed;
independent technical review has no unresolved P0/P1/P2 findings.

Live diagnosis responses include an opaque `evidence_id`, `audit_status`,
`evidence_completeness`, and `evidence_references`. Each ID names one private,
versioned `record.json` artifact under the server's configured audit directory.
File/history diagnosis tools use the same evidence contract. Validation failures
before any host execution do not create execution evidence. A tool error after
host execution includes its evidence ID and persistence status in the MCP error
content, without attaching a structured success result.

`audit_status: persisted` means the artifact was written. It does not mean the
diagnosis succeeded or that every required observation was available. The
independent `evidence_completeness` field is `complete` or `incomplete`;
`incomplete_reasons` in the record explains unavailable results, missing identity
or inventory provenance, missing diagnostic observations, and truncation. A
known nonzero command result can provide complete evidence of a negative result.
Redaction is the explicit sharing policy and is reported by `redacted`;
truncation removes observations and therefore makes evidence incomplete.

The schema version 2 record preserves the sanitized structured diagnosis and
verdict, its command evidence, return-code availability, stdout, stderr, module
message, failed/unreachable flags, outcome classification, and safety flags.
Ansible module and process-launch failures preserve `module_stdout`,
`module_stderr`, `launcher_rc`/`launcher_rc_known`, and
`module_failed`/`command_start_failed` flags separately. In these cases the requested command has no observed exit code (`rc_known: false`),
the outcome remains `unknown`, and the persisted diagnosis and retrieval report
incomplete evidence. A real command exiting 127 remains a known command result.
References use the evidence ID and a JSON-pointer fragment such as `#steps/0`.
References remain distinct when different hosts execute steps with the same ID.
The observer captures every actual step, including central service queries in
composite tools and exporter probes in the monitoring pipeline and SNMP tool.

Each step records its inventory host, resolved address, and execution interval.
Execution identities distinguish configured connection/become users from an
observed effective user. DNS architecture reuses only a successful, fixed
probe with the matching handler family, host, module and generated step ID;
ordinary command or log output containing its marker text is never identity
evidence. Other live tools collect a separate bounded `id -un` observation using
the same Ansible inventory privilege settings. The identity probe has its own execution
time and evidence. An unavailable identity is explicitly unknown and makes the
record incomplete. An injected command adapter must also provide an identity
adapter to produce observed identity evidence.

Provenance separates the running executable's SHA-256 and Go build metadata
from workspace revision/tree/modified state and inventory-source revision.
Inventory bytes and resolved inventory facts have separate SHA-256 values,
captured when inventory is resolved before execution. The resolved-facts hash
covers external inventory variables without publishing their secret values.
An unavailable build VCS revision is labeled unavailable; workspace HEAD is
never substituted for the executing server's revision.

Records are sanitized before any publication. Files use mode 0600 and call
directories use mode 0700. Publication replaces a private staging file atomically.
A preliminary artifact is explicitly unfinalized and incomplete. Once finalized,
the artifact cannot be overwritten by the evidence writer. Final-publication
failure is returned as `audit_status: failed`; it does not turn collected data
into persisted evidence.

`pilot_diagnose_evidence_get` is registered with the diagnose, active-diagnose,
and raw-diagnose tool families. It accepts only the returned opaque ID, never a
filesystem path, and performs no host commands or filesystem writes. Directory
and record opens reject symlinks; nonregular files, invalid schemas, oversized
records, and records that violate the sanitizer policy are rejected.

| Request field | Meaning |
|---|---|
| `evidence_id` | Required opaque ID returned by the diagnosis. |
| `offset` | Decoded-byte offset, initially zero. |
| `limit` | Decoded bytes per page; default and maximum 32768. |
| `sha256` | Hash from the first page; pass it on later pages to reject a changed preliminary record. |

Responses contain `data` encoded as base64, `encoding: base64`, `offset`,
`next_offset`, `total_bytes`, `eof`, the full record's `sha256`, `finalized`, and
`evidence_completeness`. Decode and concatenate pages in offset order to obtain
the entire sanitized JSON record, including every retained step and diagnosis
field. Continue from `next_offset` until `eof` is true. A changed hash requires
restarting at offset zero. Pagination preserves UTF-8 bytes without cutting or
rewriting characters. Records are bounded to 16 MiB; individual diagnostic
strings retain the existing 64 KiB sanitization bound and truncation flags.
