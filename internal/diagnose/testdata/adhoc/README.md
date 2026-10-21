Captured 2026-10-21 with Ansible 2.19 on localhost using ansible.posix.json.
The JSON retains the real stdout/stderr/rc/failed/unreachable/msg fields from
one command task. UUIDs, timing, invocation environment and unrelated fields
were omitted; the unreachable message home path was anonymized.

- both.json: python3 writes `out` to stdout, `err` to stderr and exits 7.
- stderr.json: python3 writes `stderr only` to stderr and exits 9.
- unreachable.json: actual local transport failure creating its default
  remote temporary directory under a read-only home; the two successful
  command captures used ANSIBLE_REMOTE_TEMP under /tmp.

- module-failure.json: command module rejects an unsupported parameter before
  launching argv=[python3]; no command return code exists.

Raw captures and controller stderr were retained in the generating workspace's
ignored .verification/issue-58 directory. These are parser fixtures, not proof
of SSH availability or a deployed service.
