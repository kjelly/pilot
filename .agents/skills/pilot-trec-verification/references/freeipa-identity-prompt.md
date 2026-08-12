# `freeipa-identity`: the `.vault/main.yaml` prompt

> Reference for the `pilot-trec-verification` skill.
> Read before deploying or reconciling `freeipa-identity` with a canonical roster.

---

## For a canonical roster, answer `y` — do NOT redirect the prompt at the roster path

**This rule flipped on 2026-07-25. Read the whole file before scripting this
prompt, not just the first rule you find.**

The roster is loaded **exclusively** via the `freeipa_roster_file` host var — set
on `freeipa-server`, and for this repo's minimal-poc topology also on `nexus`,
either by hand via `pilot edit`'s hosts.yml `其他變數` screen or automatically by
the NFS-role-add roster bootstrap (`edit_tui.go`'s `pushNFSRoleBootstrap`). That
host var is **completely independent** of whatever gets selected at the wizard's
vars-file prompt.

The prompt 「偵測到 …/.vault/main.yaml，這次佈署要用它當密碼變數檔嗎？」 exists to
satisfy a *different*, Go-side check: `contracts/freeipa-identity.yaml`'s
required-input preflight wants a bare top-level `ipa_admin_password` key.

A canonical (`schema_version: 1`) roster's own top-level-key gate
(`internal/inventory/roster_validate.go`'s `checkTopLevelKeys`) **rejects** a bare
`ipa_admin_password` at the roster's top level — the admin credential must live
nested under `freeipa.admin.password`. So the roster file can **never** satisfy
this contract check by itself, no matter what you answer.

**Correct sequence for a canonical roster:**

1. At 「偵測到 …/.vault/main.yaml，這次佈署要用它當密碼變數檔嗎？」 answer **`y`** —
   `.vault/main.yaml`'s own `ipa_admin_password` key satisfies the required-input
   check.
2. Nothing else. The roster loads separately via the `freeipa_roster_file` host
   var, not via this prompt.

**Answering `n` and pointing the vars-file prompt at the roster path** — the
documented sequence before this update — now fails outright with
`Error: delivery transaction failed: component "freeipa-identity" requires input
"ipa_admin_password"`, before any ansible-playbook run. `[live 2026-07-25, round
16]` No mutation happens either way, since the Go-side contract check runs before
the preview — a safe mistake to make and retry, but don't burn an attempt
rediscovering it.

## The older, non-canonical roster shape

That `n`-then-roster-path sequence was correct for an older roster shape current
around 2026-07-17 (v8), predating both the `freeipa_roster_file` host-var
mechanism and the canonical top-level-key gate. At the time the roster path was
the only way to load the roster at all, and a bare `ipa_admin_password` inside it
was legal. Answering `y` against *that* shape genuinely skipped every reconcile
task (`ok=5 skipped=50 changed=0`, initially misread as "wizard can't do
freeipa-identity").

If you are re-verifying a workspace still on that shape — no `freeipa_roster_file`
host var anywhere, a bare top-level `ipa_admin_password` inside the roster — the
original `n` sequence still applies to it. But that shape is stale: migrate to the
canonical schema documented in the runbook and
`playbooks/apply/freeipa-identity.roster.example.yaml` rather than preserving the
old prompt answer to match it.

## Either way: `changed=0` with dozens skipped is a failure

A `freeipa-identity` PLAY RECAP of `changed=0` with `skipped=` in the dozens, on a
roster that should create anything, is a **failed deploy, not a pass**.

Do not fall back to bare `ansible-playbook` for this — the wizard path above is
the sanctioned one.
