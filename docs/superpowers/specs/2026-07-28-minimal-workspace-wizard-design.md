# Minimal Workspace Wizard Design

## Goal

Add a fast, guided `pilot edit` path that creates a deploy-ready minimum
workspace while preserving the current hosts/group-vars/vault/roster editor as
an advanced path.

## Scope

The new path is a top-level `pilot edit` menu item named
`快速建立最小 workspace — 引導式設定並驗證可部署性`. It writes the same
`hosts.yml`, `group_vars/*.yml`, `host_vars/*.yml`, and `.vault/main.yaml`
files the existing screens own. It does not introduce a new workspace format,
new deploy command, or a second validation contract.

The existing menu items remain available under their current labels. A user can
leave the quick path and use any advanced editor at any time; both paths read
and write the same files.

## User Flow

1. The user chooses the quick path from `pilot edit`'s top menu.
2. The wizard opens the existing hosts editor so the user supplies host names,
   connection addresses, SSH users/keys, and role membership.
3. After hosts are saved, the wizard generates missing role-derived
   `group_vars` and the vault skeleton using existing inventory-generation
   helpers.
4. For each generated cross-role host value, the wizard presents its
   inventory-derived value as the default. The user may accept it or replace
   it. Ambiguous or absent source-role hosts are not guessed and remain a
   required correction.
5. The wizard opens the existing vault editor for only required secret fields.
   `alertmanager_config` remains optional because the built-in null-receiver
   configuration is operational.
6. The wizard runs the same workspace completeness checks used by `pilot edit`
   and the matching deploy completeness rules. A failure shows an actionable
   destination: hosts, a named group-vars file/key, or vault. Selecting the
   destination returns to the existing editor for that source.
7. A passing run displays `✅ 最小 workspace 已可部署` and the exact next
   command: `pilot inventory generate --dir <workspace>`, followed by
   `pilot deploy -i <workspace>/inventory.yml`.

## Derived Values

The source of truth is the role membership in `hosts.yml`.

| Target value | Source role | Behaviour |
| --- | --- | --- |
| `restic_s3_target_host` | `seaweedfs-s3` | Pre-fill only when exactly one source host has `ansible_host`. |
| `thanos_s3_target_host` | `seaweedfs-s3` | Same rule for Prometheus and Thanos Query. |
| `alertmanager_target_host` | `alertmanager` | Pre-fill only for exactly one source host. |
| `thanos_query_target_host` | `thanos-query` | Pre-fill only for exactly one source host. |
| `loki_target_host` | `dashboard` | Pre-fill only for exactly one source host. |
| `freeipa_server_ip` | `freeipa-server` | Pre-fill only for exactly one source host. |

The existing `groupVarsAutoHostVars`, `siteAutoHostVars`, and
`resolveSingleRoleHost` catalogs remain the shared implementation boundary;
the quick path must not duplicate a second mapping.

## Validation Contract

The quick path must not report success unless all of these are true:

- `checkWorkspaceCompleteness` reports no blocking failures.
- Every required vault key is present, non-empty, and not a `CHANGE-ME` value.
- Every group-vars either/or requirement is satisfied either by a user value,
  an external endpoint override, or an unambiguous source-role derivation.
- Required host vars, including `prometheus_site_label`, are present.
- The generated inventory can be produced successfully from the workspace.

The quick path may show non-blocking information about values it derived, but
it must never claim deployment readiness while a deploy hard gate would reject
the same workspace.

## Error Handling and Recovery

The wizard writes each existing file only through its established editor/save
path. Re-entering the quick path reads existing files and pre-fills their
current values; it never silently replaces user overrides. A failed
completeness check is recoverable in place and offers the relevant existing
editor. The wizard does not clean remote hosts or run deployment; recovery of
partial remote applies remains the responsibility of `pilot deploy`.

## Compatibility

Existing runbooks remain valid because the quick path is parallel to, not a
replacement for, the current advanced workflow. Both paths produce the same
workspace files and use the same `pilot inventory generate` and `pilot deploy`
commands. The minimal-PoC runbook should document the quick path as an
alternative entry route, not replace its existing audited sequence.

## Acceptance Criteria

- A new empty workspace can be configured through the quick path without
  opening individual group-vars files manually.
- Every derivable address is visible as a pre-filled, editable value.
- A user can override a derived address with an external endpoint.
- A missing or ambiguous derivation blocks readiness and identifies the source
  file/key to fix.
- A ready workspace passes `pilot inventory generate` and does not fail
  `pilot deploy`'s completeness gate for a value the quick path accepted.
- Existing top-level advanced editor entries and their current navigation keep
  working unchanged.
