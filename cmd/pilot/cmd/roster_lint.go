package cmd

import (
	"errors"
	"fmt"
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
	rosterLintCmd.Flags().StringVar(&rosterLintVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster (decrypted in memory; no plaintext file is written)")
	rosterCmd.AddCommand(rosterLintCmd)
	rootCmd.AddCommand(rosterCmd)
}
