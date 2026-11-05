# Shared services discovery — Issue 235

Outcome: **PASS — candidate-bound native acceptance completed.**
Run interval: 2026-11-03 06:37:31–06:39:21 UTC. The implementation candidate is
`0842f1d87c109da78de128b8da80e6b767ca9c8e`, tree
`ce0c0e41c1eaa5a999f5c579ba0fa9427fce0121`.

## Target and immutable inputs

A dedicated Ubuntu 24.04 VM acted as the native Docker host: 6 vCPU, 12 GiB RAM,
one actual inventory host, `i235-cache-host-r2`, and the same OS user (UID 0).
Its own libvirt gateway served the synthetic `i235-1103` cache profile. Existing
user stacks were outside the target scope and were not adopted or modified.

Two clean Git archives of the candidate were materialized in separate directories
inside the VM, each using the same independently fingerprinted binary and a
different VM data directory. The binary was built from an isolated archive
outside the checkout, with Go 1.26.8, GOWORK disabled and build VCS stamping
disabled; no production-source overlay was used. The source tree identifies all
committed inputs. The operator record below additionally fingerprints critical
source files, dependency locks and external test fixtures. It is an operator
record, not a generated pilot vm-target evidence schema or automatic reuse proof.

| Input | SHA-256 / revision |
|---|---|
| Unmodified legacy BASE source | `613c36162bc5cfbeac929c5b4224ec9689a54f3b` |
| BASE fixture binary | `957a9b0f540743f6a8b8681af64a5ed7dd9f34fcfe83aa6dbba250d598aa611b` |
| Candidate binary, independently checked in both archives | `08fa3f4356f7e9a12e7e6d0b023b827446f90e4150d3b856045773cfb89e0b23` |
| Disposable cloud image | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` |
| Synthetic profile | `1767d6583cea0741e8d6ac719cea147d762f0c8528a2c0468725309b78d33946` |

## Actual acceptance

| Invariant | Observed result |
|---|---|
| Valid legacy prerequisite | Unmodified BASE returned exit 0 and published configured/running state. Eleven native containers were healthy and unpaused; Harbor and Pulp admin authentication and real content reads passed. Separate observations retained the same container IDs, restart counts and credential/CA hashes. |
| Independent checkout/VM directories | Two simultaneous processes from two separate candidate archives used different VM data directories and the OS-user default discovery. Their complete status JSON matched, including one instance ID, generation 1, fingerprint, root and bind endpoint. |
| Interrupted migration | A syscall-delay fixture paused publication after the physical owner file became visible but before discovery state existed. SIGKILL returned -9. Concurrent retries recovered the reserved identity and successfully published one shared registration. This is process-crash injection, not a power-loss test. |
| In-place preservation | Adoption retained all eleven container IDs, bind mounts, generated Compose/configuration hashes, CA certificate/key and management secret bytes. No credentials, cache directory or services state were copied into either VM data directory. |
| Cache and native authentication | Fixed APT hello 2.10-3build1 payload (26,006 bytes), Pulp repository metadata (2,346 bytes), and pinned OCI manifest/config/blob files matched before adoption, after adoption and after normal down/up. Both native management APIs authenticated throughout the successful arms. |
| Conflicts before mutation | Four negative cases returned exit 1 with the specific profile, bind endpoint, physical owner or Docker project/root diagnostic. File hashes and container IDs stayed unchanged. Native exec/rename traces contained no render rename, Compose or prepare execution. A symlink discovery alias resolved to identical status/identity. |
| Native lifecycle | Down from checkout A retained data and identity. Up from checkout B returned exit 0 with the same instance/generation and preserved native authentication/content. Container recreation during explicit down/up is expected; adoption itself recreated none. |
| Purge boundary | Purge without confirmation returned the exact confirmation diagnostic and changed neither content nor containers. Confirmed purge removed only the registered cache root/projects. Unrelated content and both synthetic pre-existing VM state files remained byte-identical. Explicitly naming the historical adoption source afterward did not re-adopt it. |

The complete final native chain has a `run_check.py` receipt: exit 0, exact
candidate SHA, clean before/after and unchanged HEAD. The chain ran healthy-source
observation → content baseline → interrupted dual-process adoption → preservation
→ four traced conflicts → normal down/up → confirmation refusal and scoped purge.

## Operator machine summary

```json
{
  "schema": "operator-native-services-evidence/v1",
  "candidate": {
    "revision": "0842f1d87c109da78de128b8da80e6b767ca9c8e",
    "tree": "ce0c0e41c1eaa5a999f5c579ba0fa9427fce0121",
    "binary_sha256": "08fa3f4356f7e9a12e7e6d0b023b827446f90e4150d3b856045773cfb89e0b23"
  },
  "baseline_revision": "613c36162bc5cfbeac929c5b4224ec9689a54f3b",
  "outcome": "pass",
  "native_receipt": {
    "exit_code": 0,
    "clean_before": true,
    "clean_after": true,
    "head_unchanged": true,
    "started_at": "2026-11-03T06:37:31+00:00",
    "finished_at": "2026-11-03T06:39:21+00:00"
  },
  "target": {
    "kind": "isolated-vm-host-native-docker",
    "os": "Ubuntu 24.04",
    "uid": 0,
    "containers": 11
  },
  "proofs": {
    "independent_processes": 2,
    "independent_archives": 2,
    "distinct_vm_dirs": 2,
    "generation": 1,
    "crash_exit": -9,
    "conflicts": 4,
    "source_adoption_containers_unchanged": true,
    "ca_secrets_mounts_content_unchanged": true,
    "normal_down_up": true,
    "confirmation_refusal": true,
    "scoped_purge": true,
    "vm_state_preserved": true
  },
  "content": {
    "apt_sha256": "e68cf4365b7aa9c4e2af4af6eee1710d6f967059b7b4af62786e8870d7366333",
    "pulp_metadata_sha256": "7410fd780fe0ddb9477ccb1f3c3200e9bffec3be5d3b641bbb92b32afc943615",
    "oci_digest": "sha256:c567b231f65614688711a75f31518a064258a51d442117a3e771a3a8fdba78ef",
    "oci_file_hashes": [
      "4f55086f7dd096d48b0e49be066971a8ed996521c2e190aa21b2435a847198b4",
      "d1a8d0a4eeb63aff09f5f34d4d80505e0ba81905f36158cc3970d8e07179e59e",
      "e2ac70e7319a02c5a477f5825259bd118b94e8b02c279c67afa63adab6d8685b"
    ]
  },
  "critical_source_hashes": [
    {
      "path": "go.mod",
      "sha256": "7c24fa60e56bfe896caafdaba37b96e4acf25f40bc633accbf57ac3af805b72f"
    },
    {
      "path": "go.sum",
      "sha256": "174d65f76cfbb94eeea8b6b50718fe6969677483ebebf13a85124048b3acad08"
    },
    {
      "path": "cmd/pilot/cmd/root.go",
      "sha256": "aecc6b771ebeca1a4536e025dd4b576844e3a45f720df83f4584bfde8cc2e5b4"
    },
    {
      "path": "cmd/pilot/cmd/data_dir_state.go",
      "sha256": "382e37858ad1feb5fc976376f737ac6299af69073359205ebcd5e6e2c6a3ba83"
    },
    {
      "path": "cmd/pilot/cmd/services.go",
      "sha256": "dc01cf0995167b4e0e1e7357158643ef2de8bb9380593b84f23f436f56cb543d"
    },
    {
      "path": "cmd/pilot/cmd/vm_target.go",
      "sha256": "f8561d8b4207af24f182cea66a2c70f37213d0ff1c0149f16bbe5123cc90b5a6"
    },
    {
      "path": "cmd/pilot/cmd/vm_target_topology.go",
      "sha256": "68e994b5d9a3193b3aa988d42b020bdbd3d4bdb59721f4d133ddde25a1ca5707"
    },
    {
      "path": "internal/config/config.go",
      "sha256": "189c900c8533b2322b4a4ec4610156fabd5aef7ee7b20391412abc8e3075856f"
    },
    {
      "path": "internal/services/manager.go",
      "sha256": "541e0cb5695b3f1842b71aeb2824d44d6c4e2980bf8b5bad6a596a51912d2f40"
    },
    {
      "path": "internal/services/discovery.go",
      "sha256": "3cc0c8723d6d16d69be1b6ac9c8741a2fe98c87ebd2ff41cf99b3efe9b66d3aa"
    },
    {
      "path": "internal/services/profile.go",
      "sha256": "e10587405a39333a2ab3f7a0529317db0f9e7cedd1a3627c0eaecb66c9fe2d0a"
    },
    {
      "path": "internal/services/compose.go",
      "sha256": "396b5c7314518f482e7ba2089e5f734052781c5aad1d64b8996ee80dca05fc1a"
    },
    {
      "path": "internal/services/seed.go",
      "sha256": "238fb32965538591bdc909bf05c2df8dbdb25cac06bc830c3cb7f398ac786071"
    },
    {
      "path": "internal/statefile/statefile.go",
      "sha256": "e3252ff1d1984952ccdb90bfa72107170628d9bcc17fa419b8a244b2dc5057e5"
    },
    {
      "path": "internal/vmtarget/service_bootstrap.go",
      "sha256": "a0f8473badaa1ba7f4a9dc346454caa09e68ea1d32cf3579eb6e79e2e565c82b"
    }
  ],
  "external_fixture_hashes": [
    {
      "path": "observe.py",
      "sha256": "2728da54c13daad5935bd2b9b802741258269c93b646b8d74932b876c719765d"
    },
    {
      "path": "adopt.py",
      "sha256": "1467bf556d761760444b59a030de7b7b5d8e1f542dc0c856bd90e1215c0394f1"
    },
    {
      "path": "probe.py",
      "sha256": "f07d303928966592332edc36bfd1a0e04d43b3189edd67dcd2a97a29b7f2cd97"
    },
    {
      "path": "conflicts.py",
      "sha256": "848c2506a4314cf3d2ef0dc9a3722d9af8bf71ad7c73847550242c2a9b69b326"
    },
    {
      "path": "lifecycle.py",
      "sha256": "6765fdcae27d46dfb51e0311f2f5318c5937b3d0929126f7bd6ac935f9bc5b4e"
    }
  ]
}
```

## Native versions and images

Docker 29.1.3, Compose 2.40.3+ds1-0ubuntu1~24.04.1, Skopeo 1.13.3.
These public images were transferred into the disposable VM. IDs below are
immutable local image IDs; upstream manifest provenance was not separately
revalidated. Raw image facts include all twelve transferred images.

| Image | Local image ID SHA-256 |
|---|---|
| Pulp 3.85.25 | `fdda85e59606224b2211219c84e83b30e0609cc861d9ffb0d4f8b5767499a90f` |
| apt-cacher-ng 3.7.4-20220421 | `a2df7c66da9f529214343b7aa571ea52142eb1fb04ffd50c541bf65220b6a4b8` |
| Harbor prepare v2.15.1 | `99532c375af37d8153fe6644945d52fb2317687e268b0895b5fce91d1e6d4d62` |
| Harbor core v2.15.1 | `7ad3c287d9c9d3eddf0060fae583f25c83fb48e300373323ffee0fa91e3f2921` |
| Harbor DB v2.15.1 | `6e60aa1d05f7dccbeb7bc915189c2a08595669173aac649360bc3d99a2cdf07a` |
| Harbor jobservice v2.15.1 | `960cbf4860fa30b1afb80351c19b25289ce5c8340179e7b9b585f312b87bef89` |

## Failure paths and arms

The first environment failed during legacy setup, before candidate migration;
its previous record remains in Git history. A completely fresh dedicated VM and
data root were rebuilt. Native jobservice syslog captured connection-refused
errors fetching core internal configuration, followed by panic/restart before
core readiness. The containers later became healthy and native admin API auth
returned 200, but that initial BASE command still failed.

The successful fixture setup stopped only its Harbor project before rerunning
unmodified BASE. This avoided running prepare over live generated configuration;
the normal BASE command then completed seeding and state publication. A stable
healthy/authenticated baseline was snapshotted. The final-candidate chain started
from that healthy snapshot; no Running state, account reset, modified image or
production-source shim substituted for successful BASE publication. This setup
boundary does not prove ordinary repeated-up or authentication-repair behavior.

Earlier external harness attempts had two expectation bugs: Python tuples versus
JSON lists in mount comparison, and expecting a flag name instead of the actual
purge confirmation diagnostic. Those outputs were retained locally, the probes
were corrected without weakening value/diagnostic assertions, and the entire
final-candidate chain then passed from the healthy snapshot. Production code was
unchanged by these harness corrections.

Controlled raw artifacts outside the checkout contain `i235-results/before.json`,
`adoption.json`, both status JSON files, `adopted.json`, `restarted.json`,
`conflicts.json`, `lifecycle.json`, source exec/rename traces, external fixtures,
the native receipt/log and `native-tools-images.log`. Setup artifacts additionally
retain `base-up-first.log`, `base-up-stopped-retry.log`, native jobservice/core
syslog, inventory and stability observations. Their local location is recorded
in the Issue checkpoint; credential values and raw operational logs are not
published here. Candidate receipt and metadata hashes were rechecked together.

## Not covered / limits

This is native Docker service evidence inside a disposable VM, not an Ansible
apply/spec-verification chain. VM state preservation uses two synthetic existing
state files; real direct-bootstrap behavior is covered by executed command/Go
regressions. Topology delegation was traced to that same helper; no nested VM boot
or topology-specific native package-install run is claimed.

Native endpoints use the existing HTTP contract. CA preservation is byte equality;
this is not a new TLS deployment. Pulp content checks cover repository metadata
and authenticated repository state, not RPM payload/offline retention. Cross-user
permissions, concurrent up/down maintenance leases, healthy-up fast paths,
credential recovery, upstream byte savings and request coalescing belong to the
separate follow-up work. The pre-existing incomplete first-bootstrap CA-pair
interruption boundary is unchanged; legacy migration interruption was tested.

The evidence contains synthetic fixture identities and content/image fingerprints.
It does not establish human PR approval or GitHub CI success.
