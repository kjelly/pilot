Real ansible-playbook captures of playbooks/check/freeipa-access-drift-probe.yml
(ansible-core 2.19.2), stdout and stderr kept apart as ansible wrote them. Used
by probe_failure_test.go (issue #179). Each case ran against a localhost
inventory with a hyphenated group (freeipa-server), a roster without an admin
password, fake kinit/ipa on PATH, and:

  gate_missing                  a vault vars file without ipa_admin_password
  vault_template_unresolvable   ipa_admin_password: "{{ 1 / 0 }}"
  vault_bad_yaml                "ipa_admin_password: Sup3rS3cretPw: oops" (not YAML)
  vault_encrypted_no_password   ansible-vault encrypted vars file, no password file
  vault_wrong_password          the same file with a wrong password file
  host_unreachable              ssh to 127.0.0.1:1 (connection refused)
  kinit_censored                a fake kinit that exits 1 (the task is no_log)
  gate_missing_minimal          the gate_missing vault under ANSIBLE_STDOUT_CALLBACK=minimal
  gate_missing_force_color      the gate_missing vault under ANSIBLE_FORCE_COLOR=1 (escape codes kept)
  vault_not_mapping             a vault vars file that is a YAML list, not a mapping

Only the machine's paths were rewritten (to /work, /repo, /scratch, /home/user).
Sup3rS3cretPw is a made-up sentinel, not a credential.
