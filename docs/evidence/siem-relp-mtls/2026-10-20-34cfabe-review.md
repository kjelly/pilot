# RELP/mTLS — PR #128 recovery review

Run ID: `pr128-review-34cfabe-20261020`; operator: coding agent on the maintainer’s workstation.
Formal run: **2026-10-20 11:54:50–12:38:33 UTC**, exit **0**.
Tested candidate: `34cfabea416eb9645aaa323e541198ae39bbbe96`.
Tested tree: `67f0299bcd8a39fc77ffd0e85821e6576ebd7211`.
The formal target run and race/CI suites used separate clean isolated checkouts, without
source overlays. The ordinary suite began on identical frozen source bytes before the local
candidate commit; that worktree remained unchanged throughout execution.

The review's relative-path cleanup now addresses the actual role directory. Failed material
validation restores existing bytes, ownership and modes, removes only files absent before the
attempt, and preserves unrelated files with identical basenames. Changed sender TLS restoration
triggers a restart only after the restored global configuration validates. Recovery without changed
or failed service operations or changed TLS files leaves the loaded daemon untouched. An invalid
restored global configuration also prevents a recovery restart. Per-play recovery state is reset.

## Immutable environment and actual inventory

- CLI SHA256: `83b53659f74c5cadfbe68cf8617cfcad327de01d0af5a2e1ff83ebb9c44001be`.
  Formal orchestration SHA256: `eb33f1c7dcce657aebf41995ea4e1d815ae7cbfd30cc2b468ed38a68126f9163`.
- Actual rendered groups: `log-server = aq-log`;
  `audit-log-forwarding = aq-log, aq-ubuntu, aq-el`.
  Alignment A includes the receiver in forwarding for its local audit/auth selftest.
- Receiver/client: Ubuntu 24.04.4 LTS; second client: AlmaLinux 9.8, SELinux **Enforcing**.
  Signed runtime fixture pins rsyslog/rsyslog-relp `8.2608.0-0adiscon1noble2` and
  librelp `1.13.0-0adiscon1noble2` on Ubuntu; rsyslog/rsyslog-relp `8.2608.0-2.el9`,
  librelp `1.13.0-1.el9`, libfastjson4 `1.2304.0-1.el9` on EL.
- Go 1.26.8, native ansible-core **2.19.2**, Docker sandbox ansible-core **2.19.14**.
  Sandbox image `pilot-cli:latest` resolves to
  `sha256:2314cde33ecc42452b6019ee6039ac84d6b33ced0f6da596568c5c449fd360df`.
  `GOFLAGS=-buildvcs=false`, `ANSIBLE_FORKS=1`; unit suites use GNU timeout 9.1 and logrotate 3.21.
- Ubuntu golden image SHA256:
  `bfab799e2c50a83f77c607e50290646c07628a67ed73fe90c28658a28b0a5394`.
  AlmaLinux golden image:
  `b780998adca7c69ff6dbd41a05b51769ef6ab6708a7defbd286195186fbcc8ac`.
- RELP/mTLS on 20514; legacy TCP/514 loopback-only. Disposable test CA and per-host
  private PEM inputs; no production vault/PKI inputs. Public test CA file SHA256:
  `daff1ee5909b5ced8b0cdb6144ce0ccbd94eebbcd6cad19702c49350933535e2`.
  Private test-input bundle SHA256 (contents withheld):
  `9bcf1831ae9b95872baf3c70c47516b37ce0444ec2542aa89af3cbc71b47b507`.

| Platform | Installed binary | SHA256 |
|---|---|---|
| Ubuntu, both hosts | rsyslogd | `d8b2ffa11f9d5c3b0da328ccb1274b4f99cac3bb5201761df5185e3d11abaa9d` |
| Ubuntu, both hosts | librelp.so.0 | `577c93290bb67b79e7aaf223b978d5d562e160a68b6a8cb6589508a647694074` |
| AlmaLinux | rsyslogd | `fdf61c69a079aa3728483063764069c88a3f63d505363fed5f16164da1a1768c` |
| AlmaLinux | librelp.so.0 | `70b734ece9df98f9b01794102d4d43635659a71bd13f7f0104b275a3349ffec9` |

## Accepted target results

The canonical RELP chain ran the integrated fresh ephemeral L1 → L3 check/diff → snapshot →
L4 apply → L5 verification → L6 second apply sequence. All fresh-chain recaps had failed=0 and unreachable=0.
Both verification specs were mapped to the actual inventory groups, timeout 40 seconds.

| Phase | aq-el ok/changed | aq-log ok/changed | aq-ubuntu ok/changed |
|---|---:|---:|---:|
| Fresh L3 check/diff | 60 / 14 | 172 / 27 | 101 / 16 |
| L4 apply | 80 / 21 | 175 / 29 | 97 / 21 |
| L6 second apply | 80 / **0** | 169 / **0** | 90 / **0** |

L5: receiver **11/11**, forwarding **66/66**, total **77/77 PASS**, no skips.

A separate fresh topology first installed the same signed runtime fixture, one host at a time
using the native sanctioned vm-target runner; the canonical chain and failure applies then ran
through the immutable Docker sandbox. This avoids the observed concurrent APT index stall in
superseded setup attempts; failed setup artifacts remain private, and are not passing evidence.

| Host / role | Initial state | Files / unrelated basenames | Healthy after correct apply |
|---|---|---|---|
| aq-log / receiver | existing-relp | PASS | PASS |
| aq-log / receiver | fresh | PASS | PASS |
| aq-log / receiver | tcp-profile | PASS | PASS |
| aq-log / receiver | partial | PASS | PASS |
| aq-ubuntu / sender | existing-relp | PASS | PASS |
| aq-ubuntu / sender | fresh | PASS | PASS |
| aq-ubuntu / sender | tcp-profile | PASS | PASS |
| aq-ubuntu / sender | partial | PASS | PASS |
| aq-el / sender | existing-relp | PASS | PASS |
| aq-el / sender | fresh | PASS | PASS |
| aq-el / sender | tcp-profile | PASS | PASS |
| aq-el / sender | partial | PASS | PASS |

Each mismatched-key apply reached the production material validator after writing material,
returned nonzero with underlying Ansible exit status 2, and ran the production shared rollback.
The full logs were independently checked for the actual validator and cleanup, rather than
accepting any arbitrary failed apply. File comparisons cover bytes, presence, mode, UID/GID,
the relevant rsyslog fragment and unrelated home-directory basename sentinels.
Existing RELP cases passed the real role health/loaded-state/ACK helper **before** the recovery
apply. All twelve passed it again after applying the correct inputs.

Both fatal C19 cases reached the real rsyslog global-config validator with the global file absent,
surfaced the original failure, and kept the daemon active with the same InvocationID and forwarding
fragment hash. Their finally paths restored the global file.

After all negative cases: receiver **11/11** and forwarding **66/66**, no skips.
Whole-chain second apply: all three hosts **changed=0**, failed=0, unreachable=0 (aq-el ok=81, aq-log ok=170, aq-ubuntu ok=91).
Both sets of owned aq-* VMs were removed; the unrelated stopped VM and shared cache services
were preserved. Formal checkout tracked state remained clean before and after.

## Regression discrimination and repository checks

- The unchanged reviewed TLS rollback fails the original six real-Ansible filesystem cases.
  The accepted test covers eight combinations: sender/receiver × existing RELP, fresh, TCP
  profile, partial files; only the target directory prefix moves into an isolated test directory.
- A bounded real-Ansible control on candidate `c9e305f` reproduced restored old TLS bytes with
  new mtimes but no reload: the production loaded-state helper remained pending. The new regression
  fails on that production code and passes here. Its three cases use real slurp/copy/systemd
  modules, replacing only external service commands: valid changed restore reloads, invalid
  global configuration retains the process, unchanged material retains the process.
- The inherited C19 five-case regression executes production flow with real Ansible and external
  service command shims, including stale facts from an earlier play.
- An earlier real-VM candidate `5cba172` exposed a second failure after RELP → TCP → RELP:
  the standalone material/config/RELP ACK probes passed, but the daemon's forwarding queues failed
  with rsyslog error 2009 (classic/segmented conflict). The accepted implementation retains classic
  pins on TCP, and rejects existing unpinned TCP without positive classic evidence for **both**
  queues before changing TLS/config/runtime. An empty spool cannot prove the loaded auto engine's
  format. Ten real-Ansible guard/render cases cover this boundary and preserve backlog.
- The queue static checker now understands balanced parentheses, quoted text and Jinja.
  Its queue requirements are unchanged; seven positive/negative parser cases retain rejection of
  missing settings, zero budgets, shared spool names and unclosed syntax.

| Repository check | Actual result |
|---|---|
| Full ordinary Go suite | PASS, exit 0; 11:47:35–12:09:34 UTC; internal/spec 1,312.911 s |
| Full race Go suite | PASS, exit 0; 11:54:51–12:18:29 UTC; internal/spec 1,377.437 s |
| Focused behavioral/tag/recovery race checks | PASS, exit 0; 95.868 s |
| Build / vet / golangci-lint 2.12.1 | PASS, exit 0; lint reports 0 issues |
| Alert-rule container behaviors / identity no-op / Thanos retention | PASS, exit 0; required CI-equivalent targets completed |
| Python callback | 25/25 PASS, exit 0 |
| All-playbook L1 syntax / duplicate YAML keys | PASS, exit 0; 264 YAML files checked |
| ansible-lint L2 | Advisory findings; no L2-clean claim. Its isolated Homebrew environment lacks ansible.posix, while native L1 and the actual target runs pass. |
| Final diff secret scan | PASS, exit 0; full cumulative staged diff scanned through gitleaks stdin |

The PR remains stacked on #125. Hosted PR workflows only target main; these are local
CI-equivalent checks, not a hosted CI result for this branch. Retarget after #125 is merged.

## Retained scope and limits

This review reruns fresh apply/verification/idempotency and the recovery paths above.
The numbered 1,440/72,000-message, leaf rotation, peer withdrawal and decommission scenarios were
**not rerun on this candidate**; those observations belong to their
[original candidate](2026-10-20-be23874c.md).
No zero-loss migration or power-loss/exactly-once guarantee is added. RELP may replay uncertain
transactions, and ACK is not final-file fsync. Disk exhaustion, messages not accepted by rsyslog
and downstream Loki durability remain outside the contract. PKI lifecycle and existing spool
format migration remain operator responsibilities.

## Source fingerprints

The tested tree fixes the complete source. These hashes precede the evidence-only metadata update;
verification Commands/Expected, targets, variable contracts and executable files remain identical.

| Tracked source | SHA256 |
|---|---|
| `contracts/audit-log-forwarding.yaml` | `137c99346f9bdb5a8865d72c7042047f45a187ce3c4b98d41436ddb9f186edba` |
| `contracts/log-server.yaml` | `19c49373d092607a07e352c5eb88b189b55191a1262de61d5e491207ea70cad9` |
| `docs/verification/audit-log-forwarding.md` | `3ca671e82c8b429043ce8eb4a8aef2ce329545001ae770c924d4985d711e4a7c` |
| `docs/verification/log-server.md` | `4c1c44c2df174c8b912c8b7d717bcd770c16e90e90dbef6e7a9c6c443835ce61` |
| `group_vars/audit-log-forwarding.example.yml` | `d10468d17530923116aa3843d200b868034a481aee302510a511ecffa393a263` |
| `group_vars/log-server.example.yml` | `d00791f673c343ffaec50ba751740513ebb2e2d7461fdf92f52ceff760d6b76a` |
| `internal/spec/audit_log_forwarding_regression_test.go` | `c74f07e5fd48649d089c0d1e7b75e287293470ee4ff94f4c8d370b2ba7c8c150` |
| `internal/spec/log_server_regression_test.go` | `439004d41e489f6e04b103f5372ad58ad794bbe921e1c8774e66343129ce0e76` |
| `internal/spec/rsyslog_forward_queue_regression_test.go` | `f8aa3f1f10812293a1093bedb21a9a74d81de2cd4b853e5ce806e9b185f484de` |
| `internal/spec/siem_relp_mtls_regression_test.go` | `1a3fd3dfd775fb862c441245e45cfa234041640155ac1f6808f5dd919d66fec8` |
| `internal/spec/siem_shared_inputs_regression_test.go` | `a5f48addb8995c35265b938467bab7c7deca6b6f6f4aff07d67c27cdd620c98c` |
| `playbooks/apply/audit-log-forwarding-apply.yml` | `74ffc74b70d3713682a462579e41b886e2543718bb138a4f72f17c5ac95698ae` |
| `playbooks/apply/log-server-apply.yml` | `22e5f508ee346dcb0be5c9eb6d1d0240bff2a87f85fdb4d7c14f07150cd07657` |
| `playbooks/apply/tasks/rsyslog-relp-capability.yml` | `efdb4e9c9daaa13771ebc20d7176d337c03bf4f9f33274bf39c65444025e1b75` |
| `playbooks/apply/tasks/rsyslog-relp-inputs.yml` | `06b8b3f3f813888af8353a902d441b7fd17f8b1e75c35d6e2bf765a73f823d27` |
| `playbooks/apply/tasks/rsyslog-relp-restore.yml` | `01ccc02ad3c7e26ad498d6aa3cf71fe85d15e6930040f0270012277d834c4128` |
| `playbooks/apply/tasks/rsyslog-relp-retire.yml` | `e99b6f7d5fe43990ab574f6621bb06cc59f9b052a844824fb1a0cdac78f455b1` |
| `playbooks/apply/tasks/rsyslog-relp-tls.yml` | `0aff827ce415b44d582b0be37ef8d8c21548e2f3c17b0e1207441c69fa4a04a4` |
| `playbooks/apply/tasks/rsyslog-selinux-tcp-port.yml` | `ef7f875a577332a39098f9a13be56f45e3c51a2bbd23cf8b08bc148fd6dbf60a` |
| `playbooks/decommission/audit-log-forwarding-decommission.yml` | `f6c705b77888d4cbbf571f817c6451f8d63598c5ef5748ec810633421b81a07f` |
| `playbooks/files/pilot-siem-queue-check` | `bf73e8c789848be29233c3dd7e2360856e89bb5463f07fc0d6b3b4837df58535` |
| `playbooks/files/pilot-siem-relp-check` | `c22e66de6cba68219e881e5ed6fe38aa6c50145c92ce9801f39d74116c37981d` |
| `playbooks/test/files/adiscon-v8-stable.asc` | `dde15f3e20410baebb603d5b73b11bc5e1ac341dc7345c85939b1cacbc090ad7` |
| `playbooks/test/fixtures/audit-forward-queue-input.yml` | `ff672c9d82c2b33824bc88d8dc525d96fe9654089d12a9ccc1c5c461a2ba69ae` |
| `playbooks/test/fixtures/siem-relp-negative-input.yml` | `9ac9caf03367c578a8ba92d5fde893ce6d7fd78e6f101e47cbf68865e224558b` |
| `playbooks/test/fixtures/siem-relp-runtime.yml` | `a2765d6bc0159a5ed16bb639244997cce2d053830e14f92c82513897e0ace407` |
| `playbooks/test/siem-relp-chain.yml` | `6e6ed3e21db2a9d63ad12f2f009728b5ec6feb9d251c33990b7aee924b063642` |
| `scripts/audit-forward-queue-test.py` | `10d3e702259e88e231e97c943ec8f0e36ef1851a76404b1cb8f4db84343962a7` |
| `scripts/siem-relp-lifecycle-test.py` | `5416392d84ba69c2222ca41ed284b0c689c8bc2d6b9076f72c3ce3b8e3c3369e` |
| `scripts/siem-relp-mtls-test.py` | `017fd8a67656482d17b685b25666b92c83a1a7386cd21a0b1355079934ffe383` |
| `scripts/siem-relp-test-pki.py` | `1bdedc040b52d499103315164e9335b6f7dd99789a8607b40a4b389aeaa29abc` |
| `playbooks/test/audit-forward-queue-chain.yml` | `18793b35063b576611adc0e4f2eac74568494039bd09e04ad818da131ca810bc` |
| `playbooks/templates/audit.rules.j2` | `d847b79684efa6a784c5d4faf156c24e974605b16f2a0206fc348e616da54c80` |
| `docs/topologies/audit-forward-queue-topology.yaml` | `e26adbb609f2a8de27fd48fdf8c70f84a0c19548c6010845e8db1b8f2f4cf1e9` |
| `internal/spec/audit_forward_rescue_runtime_test.go` | `102ac33661c5bf0022d34c5d7c2fc04c40a0603f73f20a495799fc8e81aab6de` |
| `internal/spec/siem_relp_restore_behavior_test.go` | `709c35d784a4e3f3399ca69b6d8f73d43fdb7508325602a8763954d5cfd24447` |
| `internal/spec/siem_queue_engine_transition_test.go` | `92611972d926a2319eed6a3370944b888734f3641f5dd9487396f772665c7f25` |
| `scripts/audit-forward-rescue-test.py` | `1f70da0bd968f9714f708141c88c31e09dc867614432bac580b70d9ba13914e8` |
| `scripts/siem-relp-restore-test.py` | `13751fe7cf11a820d803205dfe53541cbedb3826b4beb9cd86afded040a488ae` |

## Sanitization and retention

This committed record is the standalone sanitized acceptance summary under
[the repository evidence policy](../../actual-run-evidence.md). Raw stdout/stderr, inventories,
per-case private inputs and prior failures were retained in private local verification staging,
with a SHA256 manifest; that staging is not durable public hosting.
Only fake aliases, versions, hashes and observed verdicts/counts are published. No private keys,
PEM contents, addresses, credentials or raw operational transcripts are included.
