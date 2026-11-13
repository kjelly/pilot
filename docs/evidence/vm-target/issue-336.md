# vm-target / docker-target drop the fact cache that `pilot deploy` reads — issue #336 (2026-11-13)

## Tested revision

| Item | Value |
|---|---|
| Candidate | **commit `66fcc86669cc`, tree `60607792f224c543c70cfa98e8fa43be5531fbe2`**, on `main` `ae5aaa8fa5f5` (base) |
| Checkout | the candidate and the base were each exported with `git archive` into a read-only scratch directory outside the repository; `pilot` was built in each (`pilot-head` from the candidate, `pilot-base` from `main` `ae5aaa8f`; sha256 `03976fd8d717…` and `55bb75ccf70d…`). The item's own checkout was not used to run anything |
| Target | disposable libvirt VMs `i336-a`, `i336-t1`, `i336-t2` (Ubuntu 24.04 golden image, 1–2 vCPU) and a docker-target container `i336-d` (`ubuntu:24.04`, with python3 added inside the container). The running `wsk-*` VMs of other sessions were not touched |
| Tools | ansible-core 2.19.2, libvirt/virsh 12.0.0, Docker (host engine) |
| Environment | one private `--data-dir` for every command of a run, so the lifecycle commands and the later `pilot deploy` use the same data directory. `up`/`down` of the candidate ran from a directory with **no** `ansible.cfg` |

## What was asked

`vm-target up/down` and `docker-target up/down` (and `topology up/down`) dropped
cached facts only from the cache `ansible-config` resolves from the process
working directory. `pilot deploy` pins its own cache to
`<data-dir>/ansible/fact-cache`. After a rebuild the entries of the replaced
host stayed in the cache that deploy reads. Invariant checked here: after `down`,
and again after `up` returns, the rebuilt hosts have no `s1_<host>` entry in
`<data-dir>/ansible/fact-cache`; entries of other names are kept.

## How the cache was filled

* vm-target: the real CLI path. `pilot deploy --dir <ws> --inventory <ws>/inventory.yml
  --component ntp --preview-only --data-dir <dir>`, with the inventory printed by
  `vm-target show-inventory` / `topology inventory` (the target is in group `ntp`).
  Every run ended `failed=0`, and `<dir>/ansible/fact-cache/s1_<host>` appeared.
* docker-target: `pilot deploy` rejects a docker connection in its preflight
  (`ansible_host` is not an IPv4 address), so it never reaches a play that gathers
  facts. The entry was written by `ansible <host> -m setup -a gather_subset=min` with
  `ANSIBLE_CACHE_PLUGIN=jsonfile` and `ANSIBLE_CACHE_PLUGIN_CONNECTION=<dir>/ansible/fact-cache`,
  the same two variables `prepareDeployAnsibleRuntime` sets. That is not the full
  deploy path.

## Results (base `main` vs candidate, same sequence)

| # | Target | Step | Base `main` | Candidate |
|---|---|---|---|---|
| V1 | vm-target `i336-a` (`--hosts ntp`) | deploy preview, then plant neighbours `s1_i336-a2`, `s1_other336`, then `down` | `s1_i336-a`, `s1_i336-a2`, `s1_other336` all remain | (see V2) |
| V2 | vm-target `i336-a` | `up` from a directory without `ansible.cfg`, with the base run's three entries present | — | before `up`: three entries; after `up` returns: `s1_i336-a2`, `s1_other336` (the target's own entry is gone; the VM now has IP `.15`, the stale entry recorded `.6`) |
| V3 | vm-target `i336-a` | deploy preview, then `down` from a directory without `ansible.cfg` | — | fresh facts show IP `.15`; after `down`: `s1_i336-a2`, `s1_other336` only |
| T1 | topology `i336-t1`, `i336-t2` | deploy preview on both, then `topology down` | `s1_i336-t1`, `s1_i336-t2` remain | — |
| T2 | topology | add neighbour `s1_i336-t1-neighbour`, `topology up --fresh` from a directory without `ansible.cfg` | — | after `up`: only `s1_i336-t1-neighbour` (the nodes were recreated with swapped addresses: `t1` `.6`→`.19`, `t2` `.19`→`.15`) |
| T3 | topology | deploy preview on both, then `topology down` | — | before: `s1_i336-t1`, `s1_i336-t1-neighbour`, `s1_i336-t2`; after: `s1_i336-t1-neighbour` |
| D1 | docker-target `i336-d` (`--hosts ntp`) | write the entry, `down` | `s1_i336-d` remains | — |
| D2 | docker-target | `up` with the stale entry present, write entry + neighbour `s1_i336-d-neighbour`, `down` | — | after `up`: empty; after `down`: `s1_i336-d-neighbour` only |

After the runs `vm-target list`, `docker ps -a`, `virsh list --all` and the
libvirt network XML show no `i336-*` target or reservation; one DHCP lease record
for `i336-t2` remained until its own expiry.

## Failure paths observed

* The new fail-closed gate fired on a real target: with a scratch data directory
  whose `ansible/fact-cache` was made a regular file, `vm-target up --name i336-gate`
  from the candidate exited 1 with `vmtarget: drop cached Ansible facts for
  [i336-gate]: drop the deploy fact cache: read fact cache directory …/ansible/fact-cache:
  … not a directory`. After it `vm-target list` was empty and there was no libvirt
  domain, overlay directory or network reservation for `i336-gate`.
* The first attempt at the docker-target run called `pilot deploy` and stopped in
  the preflight (`ansible_host = "i336-d"` is not a valid IPv4). That is the existing
  preflight rule, unrelated to this change; the entry was then written as described
  under "How the cache was filled".
* A first attempt to read `ansible_machine_id` from the cache file failed because
  Ansible 2.19 stores the facts as a JSON string in `__payload__`. The comparison
  used `ansible_default_ipv4` instead. The golden image was observed to give a
  rebuilt VM the same machine-id, so the machine-id was not used to tell them apart.

## Not covered

* Every inventory in these runs came from `vm-target show-inventory`,
  `topology inventory` or `docker-target show-inventory`, so each host key equals the
  target's own name. The removal matches cache file names against the target name
  and its `--hosts` aliases; a hand-written inventory (for example a `hosts.yml` in
  the minimal PoC flow) whose host key differs from the target's name is not cleared,
  and this run neither exercised nor proved that case.
* The ambient `ansible.cfg` cache purge was not exercised on a real target: every
  candidate lifecycle command ran from a directory without `ansible.cfg`. That half is
  covered only by the tests of the change, and by the unchanged earlier behavior.
* `pilot host decommission` and `vm-target reset`/`rollback` still do not drop any
  fact cache (unchanged by this candidate; tracked separately).
* A `pilot deploy` run with a different data directory than the lifecycle command
  reads another cache; that is documented, not exercised here.
* Only the cache that `pilot deploy` pins was driven through the real deploy
  command; the docker-target entry was written by an ad-hoc `ansible -m setup` with
  the same variables.
* The AlmaLinux image, `--services local`, and a `~` or relative `data_dir` were not run.
* The real-Ansible unit test (`TestDropAll_RealAnsibleDeployRuntime`) skips where
  `ansible` is not installed; CI installs ansible-core only for the `spec` shard.

## Record notes

Hand-written: `vm-target test --evidence-record` does not apply to this flow (no
playbook or spec changed). Redaction: neighbour names are synthetic, addresses are
shown as their last octet, and the raw outputs and binaries stayed outside Git.
Run date 2026-11-13 (local time); the addresses quoted above come from the libvirt
pool shared with other sessions' VMs, so they are not stable between runs.
