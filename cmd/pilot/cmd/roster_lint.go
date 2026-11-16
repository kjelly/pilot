package cmd

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/inventory"
)

var rosterCmd = &cobra.Command{
	Use:   "roster",
	Short: "Validate a canonical freeipa-identity roster file",
}

var (
	rosterLintUpgrade           bool
	rosterLintVaultPasswordFile string
	rosterLintVarsFile          string
)

var rosterLintCmd = &cobra.Command{
	Use:   "lint <roster-file>",
	Short: "Check a roster against the same rules freeipa-identity-apply.yml enforces at real-apply time",
	Long: `pilot roster lint mirrors freeipa-identity-apply.yml's "Gate: canonical
..." assert chain in Go — user/group/host field validation, group category
name-prefix rules, HBAC/sudo subject and target referential integrity, and
the sudo command denylist — so a mistake (a dangling group reference, an
unsafe sudo command, a missing name prefix) is caught by reading the file
directly, without needing an inventory or running ansible-playbook at all.

A roster that passes this should also pass those Ansible gates; this does
not replace running a real --check apply, since it only checks the
roster's own structure, not the rest of the inventory.

An ansible-vault-encrypted roster needs --vault-password-file: lint
decrypts it in memory with ` + "`ansible-vault view`" + ` (the same decryption
` + "`pilot roster migrate`" + ` uses), writes no plaintext file, and prints
the same report it prints for the plaintext roster. The flag is not read
for a plaintext roster.

A roster string can refer to a variable — password.initial:
'{{ ipa_default_initial_password }}' — that apply resolves from the vars file
` + "(`-e @.vault/main.yaml`)" + `; when the vars file lacks it, apply fails inside a
no_log task (its fatal result is censored), so mid-run, after the dependency
chain (freeipa-server, say) has been applied. With --vars-file lint reads the
vars file's top-level variable names (never its values) and reports every
freeipa.admin.password and users[].password.initial reference that file does
not define, as "[roster-reference] <field> references <name>, which <file>
does not define", with the other violations. Only a bare {{ name }} (or
{{ name.attr }}) is checked: a value with a filter such as default(''), an
operator, a call or a {% %} block cannot be judged without evaluating it and
is never reported, nor are !unsafe and inline !vault values, Jinja's and
Ansible's own names (inventory_hostname, ansible_*, ...) and the names the
freeipa-identity and freeipa-nfs-server playbooks define for themselves (stage,
ipa_domain, ipa_realm, ...). The names the inventory itself defines
(group_vars, host_vars) are not known to lint: for a variable only the
inventory defines, ` + "`pilot deploy`" + ` and ` + "`pilot reconcile`" + ` make the same check with
them taken into account. Lint also does not know which playbook will apply the
roster, so it reports every admin and every user reference; deploy and
reconcile judge only the fields the playbook renders for that run (the admin
password only when ipa_admin_password is not set or the roster declares no
freeipa.server — an empty string is not a declaration, null is — for
freeipa-identity; no user password for freeipa-nfs-server), so a lint finding
for a field a run does not render is a finding deploy would not refuse.

--vars-file is never found on its own: without it lint reads and prints exactly
what it always did. A missing, unreadable or non-YAML vars file, or an
encrypted one without --vault-password-file, is an error. An encrypted vars file is decrypted in
memory with the same --vault-password-file as the roster, so both must be
encrypted with one vault password.

A structurally valid roster below the current schema version passes with a
notice pointing at ` + "`pilot roster migrate`" + `; pass --upgrade to have
lint perform that upgrade itself (via the same migration engine, not a
second one) before reporting. An encrypted roster is upgraded and
re-encrypted with the same --vault-password-file, exactly as
` + "`pilot roster migrate --vault-password-file`" + ` does. Without --upgrade,
lint only reads the roster.

A hostgroup/netgroup membership or HBAC/sudo target naming a host with no
present roster hosts: entry is reported as a warning, not a structural
violation (a roster can be widely deployed with this drift already, so
lint stays non-blocking here) — but it is exactly what makes the outbound
webhook's snapshot fail closed (design spec §11.4), so it is worth fixing
even though lint still exits 0.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		// One read of path; an encrypted roster is decrypted into memory,
		// never into a file. Everything below works on these bytes, so the
		// report is the same whether the roster is encrypted or not.
		plaintext, encrypted, err := inventory.ReadRosterPlaintext(path, rosterLintVaultPasswordFile)
		if err != nil {
			if errors.Is(err, inventory.ErrRosterEncrypted) {
				return fmt.Errorf("%s is ansible-vault encrypted; rerun with --vault-password-file <path>", path)
			}
			return err
		}
		var root map[string]any
		if err := yaml.Unmarshal(plaintext, &root); err != nil {
			return rosterLintParseError(path, encrypted, err)
		}

		violations := inventory.ValidateRoster(root)
		if rosterLintVarsFile != "" {
			references, err := rosterLintReferenceViolations(path, plaintext, rosterLintVarsFile, rosterLintVaultPasswordFile)
			if err != nil {
				return err
			}
			violations = append(violations, references...)
		}
		if len(violations) > 0 {
			for _, v := range violations {
				fmt.Fprintln(cmd.OutOrStdout(), v.String())
			}
			return fmt.Errorf("%d issue(s) found", len(violations))
		}

		// Deprecation warnings never affect exit status or violate lint
		// (spec.md §8) — printWarnings runs after every "ok:"/notice line
		// below, exactly like the freeipa-identity.md example output.
		// --upgrade remains purely about schema migration; it does not
		// touch or remove deprecated-category groups, so the warning
		// still applies just as much after upgrading.
		warnings := inventory.RosterDeprecationWarnings(root)
		warnings = append(warnings, inventory.RosterDanglingHostReferenceWarnings(root)...)
		printWarnings := func() {
			for _, w := range warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w.Detail)
			}
		}

		// No structural violations: report which schema version passed
		// and, below the current version, nudge toward `pilot roster
		// migrate`. This only detects the declared version for display —
		// it is not a second validation pass; ValidateRoster above already
		// did the only one.
		version, err := inventory.DetectRosterSchemaVersion(plaintext)
		if err != nil {
			// Violations were already empty, so this shouldn't happen in
			// practice; fall back rather than fail oddly.
			fmt.Fprintln(cmd.OutOrStdout(), "ok: no issues found")
			printWarnings()
			return nil
		}

		if rosterLintUpgrade && version != inventory.CurrentRosterSchemaVersion {
			result, err := inventory.MigrateRosterFile(path, inventory.RosterMigrationOptions{VaultPasswordFile: rosterLintVaultPasswordFile})
			if err != nil {
				return err
			}
			printRosterMigrationResult(cmd.OutOrStdout(), path, result, false)
			printWarnings()
			return nil
		}

		switch {
		case version == inventory.CurrentRosterSchemaVersion:
			fmt.Fprintf(cmd.OutOrStdout(), "ok: schema v%d; no issues found\n", version)
		case version < inventory.CurrentRosterSchemaVersion:
			fmt.Fprintf(cmd.OutOrStdout(), "ok: schema v%d is valid\n", version)
			fmt.Fprintf(cmd.OutOrStdout(), "notice: current schema is v%d; run `pilot roster migrate %s`\n", inventory.CurrentRosterSchemaVersion, path)
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "ok: schema v%d is valid\n", version)
		}
		printWarnings()
		return nil
	},
}

// rosterLintReferenceViolations is the findings of lint's --vars-file: every
// secret reference of the roster that the vars file does not define. The
// vars file is read the strict way an explicit --vars-file always is
// (resolveDriftVarsFile: it must exist, not be a directory, be readable, and,
// when encrypted, come with --vault-password-file). Neither the findings nor
// the errors hold a value of the roster or the vars file: names, field
// labels and line numbers only (inventory.VarsFileNames).
func rosterLintReferenceViolations(rosterPath string, rosterPlaintext []byte, varsFile, vaultPasswordFile string) ([]inventory.RosterViolation, error) {
	abs, err := resolveDriftVarsFile(io.Discard, "", varsFile, vaultPasswordFile)
	if err != nil {
		return nil, err
	}
	names, err := inventory.ReadVarsFileNames(abs, vaultPasswordFile)
	if err != nil {
		if errors.Is(err, inventory.ErrVarsFileEncrypted) {
			return nil, fmt.Errorf("--vars-file %s is ansible-vault encrypted; rerun with --vault-password-file <path>", varsFile)
		}
		return nil, fmt.Errorf("--vars-file %s: %w", varsFile, err)
	}
	refs, _, err := inventory.RosterSecretVarReferences(rosterPlaintext)
	if err != nil {
		return nil, fmt.Errorf("check the references in roster %s: %w", rosterPath, err)
	}
	var out []inventory.RosterViolation
	// The playbooks' own names (stage, ipa_realm, ...) are known to both consumers'
	// runs; lint does not know the consumer, so it takes them all as defined.
	for _, ref := range inventory.MissingRosterVarReferences(refs, names, inventory.RosterPlaybookKnownNames()) {
		out = append(out, ref.Violation(varsFile))
	}
	return out, nil
}

// yamlErrorLine matches the "line N" positions in a yaml.v3 error.
var yamlErrorLine = regexp.MustCompile(`line \d+`)

// rosterLintParseError is lint's error for a roster that is not a YAML
// mapping. yaml.v3's type errors quote part of the offending value, which
// for an encrypted roster is decrypted text, so for one only the line
// numbers are kept.
func rosterLintParseError(path string, encrypted bool, err error) error {
	if !encrypted {
		return fmt.Errorf("parse roster %s: %w", path, err)
	}
	where := ""
	if lines := yamlErrorLine.FindAllString(err.Error(), -1); len(lines) > 0 {
		where = " at " + strings.Join(lines, ", ")
	}
	return fmt.Errorf("parse roster %s: the decrypted roster is not valid roster YAML%s (YAML error withheld because it can quote decrypted text; open the roster with ansible-vault edit to fix it)", path, where)
}

func init() {
	rosterLintCmd.Flags().BoolVar(&rosterLintUpgrade, "upgrade", false, "if the roster isn't the current schema version, upgrade it via the same engine as `pilot roster migrate` before reporting")
	rosterLintCmd.Flags().StringVar(&rosterLintVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster and for an encrypted --vars-file, which then share one vault password (decrypted in memory; no plaintext file is written)")
	rosterLintCmd.Flags().StringVar(&rosterLintVarsFile, "vars-file", "", "ansible vars file (e.g. .vault/main.yaml, plain or ansible-vault encrypted) the roster's {{ name }} password references must be defined in; reports the missing names, never values (never searched for: without this flag lint does not check references)")
	rosterCmd.AddCommand(rosterLintCmd)
	rootCmd.AddCommand(rosterCmd)
}
