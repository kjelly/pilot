# container-in-vmtesting.md -- docker/podman inside a vm-target

When your apply playbook runs `community.docker.docker_container`
inside a `pilot vm-target` host, you add an extra layer of indirection
that breaks several assumptions. This file documents the traps and the
patterns.

## Trap 1: image entrypoint is often missing or broken

`docker inspect` reports an ENTRYPOINT that does not actually exist
inside the image. Example: `quay.io/freeipa/freeipa-server:almalinux-9`
reports `["/usr/local/sbin/init"]`, but `find / -name init` inside the
container finds nothing. Any container that relies on the default
entrypoint exits immediately.

**Pattern**: always override `entrypoint:` in your
`community.docker.docker_container` task unless you have verified the
image's actual entrypoint binary by exec'ing into a one-shot container
first.

```yaml
# CORRECT: override the entrypoint to a guaranteed-existing binary
community.docker.docker_container:
  name: my-service
  image: some/image:tag
  entrypoint: ["/bin/bash", "-c", "my-service start; exec sleep infinity"]
```

## Trap 2: PATH inside a container started with /bin/sh

`docker exec <container> sh -c 'mycommand'` runs `sh` with a near-empty
PATH (no `/usr/sbin`, no `/usr/local/bin`). The selfsame `mycommand`
works fine when run via `docker exec <container> mycommand` because
`docker exec` uses the image's default `$PATH`.

**Pattern**: do not use `sh -c` indirection inside `docker exec`. Run
the binary directly, or use `bash -l` (login shell) if you need env vars.

```bash
# BROKEN: ipactl not in $PATH
docker exec <container> sh -c "ipactl status; sleep infinity"

# CORRECT: direct binary
docker exec <container> /usr/sbin/ipactl status

# CORRECT: login shell (loads /etc/profile.d/*.sh with PATH)
docker exec <container> bash -lc 'ipactl status'
```

## Trap 3: bind-mount survives vm-target down

Playbooks that use `volumes: ["/host/path:/container/data:Z"]` write
state **outside** the VM's qcow2. A subsequent `vm-target up` reuses
the same host directory. This is great for idempotency (re-applying
skips already-installed services) and terrible for debugging (a
half-baked install silently masks the real failure).

**Pattern**: after a failed run, delete the per-target dir:

```bash
pilot vm-target down --name <name>
sudo rm -rf /var/lib/libvirt/images/pilot/<name>
```

## Trap 4: community.docker.docker_container detach:false does not surface exit codes

When `detach: false` (the container runs in the foreground and ansible
blocks until it exits), the module's `register` captures container
state (created/running/exited), **not** the command's exit code. A
container that exits with rc != 0 still shows `changed: true` if the
container reached the `exited` state.

**Pattern**: for one-shot install containers, use
`ansible.builtin.command: docker run --rm ...` instead of
`community.docker.docker_container`. The `command` module captures the
real exit code.

```yaml
# BROKEN: install failure is silent
- name: "Install my service (one-shot)"
  community.docker.docker_container:
    name: "{{ container }}-install"
    image: "{{ image }}"
    detach: false
    cleanup: true
    entrypoint: some-installer
    command: ["-U", ...]

# CORRECT: real exit code surfaced
- name: "Install my service (one-shot)"
  ansible.builtin.command: >-
    docker run --rm --network host --privileged
    -v /var/lib/pilot/my-svc:/data:Z
    -h {{ fqdn }}
    {{ image }}
    some-installer -U ...
  register: install_out
  changed_when: install_out.rc == 0 and 'Already installed' not in install_out.stdout
  failed_when: install_out.rc != 0
```

## Trap 5: the host's cloud-init injects Ubuntu PATH into containers

When a container is started by the playbook running on a cloud-init
Ubuntu VM, the container inherits the host's `$PATH` through the
docker engine's exec environment. The path includes
`/usr/games:/usr/local/games:/snap/bin` (Ubuntu 24.04 defaults),
which makes you think the container runs Ubuntu even when
`/etc/os-release` says AlmaLinux 9.x.

**Pattern**: ignore the PATH noise. Trust `/etc/os-release`, not
`env | grep PATH`.

## Trap 6: host networking + systemd-in-container needs cgroups

Many server images (FreeIPA, keycloak) hard-require `--network host`
and `--privileged` because they open dozens of ports and some of them
depend on reverse-DNS. `--privileged` is heavy; a future hardening
pass can replace it with `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN`,
but for initial bring-up, `--privileged` is fine.
