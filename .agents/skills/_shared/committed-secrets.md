# No secrets in anything that reaches Git or GitHub

Every skill that commits a file or posts text to GitHub follows this. Skills refer
to it by the repo-root path `.agents/skills/_shared/committed-secrets.md` (or its
copy in the verified snapshot, `$SNAP/.agents/skills/_shared/committed-secrets.md`),
never by a relative link.

## Scope

- Every committed file: evidence records under `docs/evidence/**` (the
  pilot-generated part and the hand-written sections), `LATEST.md`, runbooks, specs,
  test fixtures and golden files (especially the real captures AGENTS.md §5.6
  requires) and literals in tests.
- Everything posted to GitHub: PR bodies and comments, Issue bodies, review comments.

The repository is public and a push is publication. A later commit does not undo it:
GitHub keeps every PR's `refs/pull/N/head`, and a squash-merge only keeps a commit
off `main`. Only revoking the credential limits the damage.

## What counts as a secret

Never write the value. This holds for disposable lab accounts and for passwords you
generated yourself.

- Passwords and passphrases: vault values (`ipa_admin_password`, `ipa_dm_password`,
  ...), passwords of users, canary and test accounts, vault password files.
- Password equivalents and values derived from a secret: the NT hash (`ipanthash`),
  `userpassword` hashes, Kerberos keys and keytabs (`krbprincipalkey`), OTP keys
  (`ipatokenotpkey`). An unsalted hash is not a safe public summary.
- Session and access material: cookies (`ipa_session=`), `Authorization` and
  `Cookie` headers, bearer and API tokens, S3 access keys, private keys
  (`-----BEGIN ... PRIVATE KEY-----`).

Refer to a secret by its vault key name or as `<redacted>`. Never write its value, a
hash of it or a prefix of it.

## Where secrets get in

1. **Real captures.** An admin request with `all`/`--all`/`--raw` returns secret
   attributes. PR #255 committed a lab user's `ipanthash` this way, in a raw
   `user_find` capture written straight into `testdata/`.
   - Ask only for the attributes the test needs.
   - Otherwise redact before the file enters the working tree. Keep the raw
     capture in `.verification/` or `/tmp`. Write to `testdata/` a copy in which
     every secret-bearing value is replaced by a fixed placeholder, keeping the
     field shape so that parsers still see the field.
   - FreeIPA JSON uses `{"__base64__": "AAAAAAAAAAAAAAAAAAAAAA=="}`, enforced only
     for `internal/freeiparpc/testdata` by `internal/freeiparpc/fixture_secrets_test.go`.
   - A change that adds real captures elsewhere from a service that can return
     secrets adds the same kind of guard test for its package.
2. **Evidence records.** `pilot ... --evidence-record` masks only the values it
   learns from `-e @file` and inline extra-vars in the steps it captures. It does
   not mask:
   - encrypted vault values;
   - derived values such as hashes and keys;
   - values you typed or generated outside those flags;
   - the hand-written sections (failure paths, not covered).

   Check those yourself.
3. **Runbooks, specs, PR and Issue text, review comments.** Command lines show
   `-e @~/.vault/<file>.yaml`, never a value. Quote command output only after
   redacting it.
4. **trec casts.** They are never committed (AGENTS.md §7). Declare
   `--secret-env`/`--secret-file` as `pilot-trec-verification` says.

## The scanner and the gates

`.agents/skills/_shared/scripts/secret_scan.py` (standard library and git only) scans **every
commit** of `BASE..HEAD`: each commit's added lines, its message and its paths. It does not look at
the final diff alone, because a value that a later commit replaces is still in the earlier one.
It reports the class, the file and the commit, never the value. It decides by the shape of a value,
not by a name that merely contains "password":

| Class | What it catches |
|---|---|
| `freeipa-secret-attribute` | the four attributes in the list above used as a key, with anything but the fixture placeholder as the value |
| `private-key` | a `-----BEGIN ... PRIVATE KEY-----` header followed by a key body (a bare header in code or a regex is fine) |
| `authorization-header` | `Authorization:` with a bearer, basic, negotiate, digest or token credential, or a long bare token |
| `cookie-header` | `Cookie:` or `Set-Cookie:` with a credential-shaped `name=value` |
| `ipa-session` | `ipa_session=` followed by a session value |
| `known-value` | a value you supply with `--secret-file` (see below) |

The three gates run it over every commit of the branch and refuse it on any finding:
`issue_gate.py` (also `create_pr.py`, `mark_ready.py`), `pr_gate.py` and
`review_gate.py` (also `apply_decision.py`). Evidence-only paths such as `docs/evidence/**` are
scanned like any other path. A gate that cannot scan (an object missing from the clone, a scanner
that does not load, an unusable `--secret-file`) refuses; it never skips.

## Before every commit and every push

1. Before each commit, read every added line of the staged diff, including hand-written
   evidence sections and new `testdata/` files. A placeholder, a vault key name, `no_log` or a
   variable reference is fine. A value is not.
2. Before each push, run the scanner over every commit you are about to push. Use
   `@{upstream}..HEAD`, or the base for a branch that has no upstream yet:

   ```bash
   python3 "$SNAP/.agents/skills/_shared/scripts/secret_scan.py" \
     --repo "$REPO_ROOT" --base "@{upstream}" --head HEAD
   ```

   Exit status 0 is clean, 1 means findings, 2 means the scan could not complete (for
   example a base commit you have not fetched). Anything but 0 stops the push.
3. To look for the values you know of (the vault, generated lab passwords), put them one per line in a
   file **outside** the repository (each between 8 bytes and 64 KiB), and add `--secret-file`. The scanner
   matches the bytes in added lines, commit messages and paths, and names a file and line, never the
   value. The gates take the same option. Do not type the value on a command line.

   ```bash
   python3 "$SNAP/.agents/skills/_shared/scripts/secret_scan.py" \
     --repo "$REPO_ROOT" --base "$BASE" --head HEAD --secret-file /path/outside/the/repo/known.txt
   ```

## Writing tests that carry trigger shapes

A test that needs a credential-shaped value builds it at run time (`secrets`, `os.urandom`, string
concatenation such as `"-----BEGIN " + ...`) inside a temporary repository or directory. It never
writes the value into a file of this repository, so the scanner's own tests and every later PR
stay clean. `.agents/skills/_shared/tests/test_secret_scan.py` scans every skill file, this one
included.

Synthetic test material that is already in the repository can still match a class when a later PR
edits those lines. `.github/secret-scan.json` names such a file (`class`, `path_glob`, `reason`); keep
the entries few and specific. The gates read it from the base branch only, so a PR cannot exempt
itself, and a `known-value` match can never be exempted. A malformed file is an error, not a pass.

## When a secret was committed or pushed

- Stop. Do not merge, do not push more on top, and do not count a scrubbing commit as
  the fix. There is no override in the gates: a finding stays a finding for as long as
  the commit is in the range.
- Report to the user:
  - the secret by name, never by value;
  - the commits that hold it;
  - whether they were pushed.
- The user decides:
  - revoking or rotating the credential, or confirming that the account and every
    use of that password are gone;
  - what to do with history. Rewriting local, unpushed commits needs their go-ahead.
    These skills never force-push. Removing `refs/pull/N/head` and cached views
    needs GitHub Support.
- **Reviewers:** a secret in any commit of the PR range is a leaked secret, P0 in
  `.agents/skills/issue-to-pr/references/severity.md`, even when HEAD no longer has
  it.
  - Search the whole range (`git log -p BASE..HEAD`), not only the final diff.
  - The finding stays blocking until the user has recorded on the PR that the
    credential is revoked, rotated or confirmed dead, and how the history is
    handled.
