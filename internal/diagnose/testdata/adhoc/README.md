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

PR #131 execution-layer captures, 2026-10-21, ansible-core 2.19.2:

- bad-interpreter.json: local inventory sets ansible_python_interpreter to
  /nonexistent/pilot-review-python; requested command /bin/true never starts.
  module_stdout/module_stderr and rc=127 describe the Ansible module launcher.
- command-rc7.json: valid /usr/bin/python3 interpreter; requested Python command
  prints out/err and exits 7. Its cmd/start/end/delta fields are retained.
- command-rc127.json: /bin/sh exits 127 after starting normally, using the
  same numeric code as the bad-interpreter wrapper while retaining timing.
- missing-executable.json: command module cannot spawn
  /nonexistent/pilot-review-command; rc=2 is errno, not a command exit.
- not-executable.json: command module cannot spawn a mode-0600 shell script;
  rc=13 is errno. Only its workspace-specific cmd path was anonymized.

These fixtures retain the actual diagnostic fields and execution metadata;
callback IDs, timestamps outside command start/end, invocation and unrelated
fields were omitted. Raw callback stdout and controller stderr were saved under
.verification/pr131-module-failure in the generating workspace.
The installed Ansible command.py initializes command timing, then calls
module.run_command; the spawn-error fail_json path in module_utils/basic.py
returns cmd/errno without start/end. Detection uses these field shapes and
module_* presence, including empty strings, rather than message wording.
