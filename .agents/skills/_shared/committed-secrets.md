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

## Before every commit and every push

Check every added line of the staged diff, including hand-written evidence sections
and new `testdata/` files.

1. Look for the names above next to a real value:

   ```bash
   git diff --cached -U0 | grep -n -i -E '^\+.*(passw|secret|token|ipanthash|krbprincipalkey|ipatokenotpkey|ipa_session|authorization:|cookie:|PRIVATE KEY)'
   ```

   A placeholder, a vault key name, `no_log` or a variable reference is fine. A
   value is not.
2. Look for each secret value you know of (the vault, generated lab passwords)
   without printing it. In bash, keep the value off the command line:

   ```bash
   git diff --cached -U0 | grep -F -q -f <(printf '%s\n' "$SECRET") && echo FOUND
   ```

Before pushing, run the same checks over every commit you are about to push
(`git log -p @{upstream}..HEAD`, or `BASE..HEAD` for a new branch). A value removed
in a later commit is still in the earlier one.

## When a secret was committed or pushed

- Stop. Do not merge, do not push more on top, and do not count a scrubbing commit as
  the fix.
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
