package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var (
	// invGenDir mirrors `pilot edit --dir`: when set (and --in/--out
	// aren't explicitly overridden) it relocates the default --in/--out
	// paths under that folder, so multiple environments each keep their
	// own hosts.yml/inventory.yml/group_vars/ bundle without having to
	// spell out --in/--out by hand every time.
	invGenDir string
	invGenIn  string
	invGenOut string
	// invGenNoGroupVars opts OUT of the default-on group_vars backfill
	// (see copyMissingGroupVars). Runs regardless of --out (even "-" for
	// stdout) since it's an independent, non-destructive side effect —
	// status lines go to STDERR specifically so they never land in
	// stdout when `--out -` is piped straight into `> inventory.yml`.
	// The group_vars/ it writes to lives next to wherever --out points
	// (see groupVarsBaseDir) — inside the pilot-cli Docker image that
	// directory is under /pilot, which is NOT bind-mounted read-write by
	// the per-file `-v .../group_vars/xxx.yml:/pilot/group_vars/xxx.yml:ro`
	// pattern DELIVERY.md currently documents, so files written here
	// would vanish with the container. Mount the whole group_vars/
	// directory read-write (`-v $(pwd)/group_vars:/pilot/group_vars`) to
	// have this persist to the host under Docker; running via
	// `go run ./cmd/pilot` locally needs no such caveat.
	invGenNoGroupVars bool
	// invGenNoVault opts OUT of generating a plaintext vault skeleton
	// next to the generated inventory bundle. Like group_vars backfill,
	// the skeleton is only created when missing and never overwrites an
	// existing file.
	invGenNoVault bool
	// invGenVaultOut is the vault skeleton path. When not set
	// explicitly, it follows --dir just like the default inventory/group_vars
	// bundle, landing under <dir>/.vault/main.yaml.
	invGenVaultOut string
	// invGenNoHostVars opts OUT of scaffolding host_vars/<host>.yml for
	// hosts whose roles have no safe cross-host default (e.g.
	// prometheus_site_label). Like the vault skeleton, this only ever
	// writes a placeholder — it never invents the real per-host value —
	// and only when the file is missing, never overwriting one already
	// filled in.
	invGenNoHostVars bool
	// invGenNoNFSRoster opts OUT of auto-completing a missing nfs.servers
	// entry in the freeipa-identity roster for hosts carrying
	// freeipa-nfs-server. Unlike host_vars/vault scaffolding, this one
	// value (the NFS service principal) is fully derived from data pilot
	// already has, so it's safe to write for real rather than only
	// placeholder — but it still never touches an already-matching entry.
	invGenNoNFSRoster bool
	invLintIn         string
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Generate/lint the Ansible inventory from a simple host->roles source file",
	Long: `pilot inventory expands a flat "host -> roles" source file (see
hosts.example.yml) into the full nested Ansible inventory.yml that
playbooks/*.yml actually target — so you maintain one list of "this
host runs these roles" instead of hand-syncing all.hosts and every
children: group it needs to appear in.`,
}

var inventoryGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Render a simple hosts source file into a full Ansible inventory.yml",
	RunE: func(cmd *cobra.Command, args []string) error {
		in, out := resolveGenPaths(invGenDir, invGenIn, invGenOut, cmd.Flags().Changed("in"), cmd.Flags().Changed("out"))
		vaultOut := resolveGenVaultPath(out, invGenVaultOut, cmd.Flags().Changed("vault-out"))

		data, err := os.ReadFile(in)
		if err != nil {
			return fmt.Errorf("read %s: %w", in, err)
		}
		hf, err := inventory.Parse(data)
		if err != nil {
			return err
		}
		rendered, err := inventory.Generate(hf)
		if err != nil {
			return err
		}
		if !invGenNoGroupVars {
			// Before printing/writing the inventory itself: keeps stdout
			// clean for `--out -` (piped straight into `> inventory.yml`
			// on the host) regardless of call order, but doing it first
			// also means a group_vars write failure surfaces before we've
			// claimed success on the inventory itself.
			copyMissingGroupVars(cmd.ErrOrStderr(), groupVarsBaseDir(out), inventory.GroupVarsStems(hf))
			copyMissingNestedGroupVarsExamples(cmd.ErrOrStderr(), groupVarsBaseDir(out), inventory.UsedRoles(hf))
		}
		if !invGenNoVault {
			writeMissingVaultSkeleton(cmd.ErrOrStderr(), vaultOut, hf)
		}
		if !invGenNoHostVars {
			writeMissingHostVarsSkeleton(cmd.ErrOrStderr(), groupVarsBaseDir(out), hf)
		}
		if !invGenNoNFSRoster {
			writeMissingNFSRosterEntries(cmd.ErrOrStderr(), groupVarsBaseDir(out), hf)
		}
		if out == "" || out == "-" {
			fmt.Print(rendered)
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
		}
		if err := os.WriteFile(out, []byte(rendered), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
		fmt.Printf("wrote %s\n", out)
		return nil
	},
}

// resolveGenPaths applies invGenDir's directory to the --in/--out
// defaults, mirroring `pilot edit --dir`. An explicitly-set --in/--out
// (inChanged/outChanged) always wins over --dir, and "--out -" (stdout)
// has no directory of its own so --dir never touches it.
func resolveGenPaths(dir, in, out string, inChanged, outChanged bool) (string, string) {
	if dir == "." {
		return in, out
	}
	if !inChanged {
		in = filepath.Join(dir, in)
	}
	if !outChanged && out != "-" {
		out = filepath.Join(dir, out)
	}
	return in, out
}

// resolveGenArtifactPath follows the generated inventory bundle by default:
// unless explicitly overridden, sidecars like .vault/main.yaml land next to
// the generated inventory (same base dir as group_varsBaseDir).
func resolveGenArtifactPath(out, path string, changed bool) string {
	if changed {
		return path
	}
	return filepath.Join(groupVarsBaseDir(out), path)
}

func resolveGenVaultPath(out, path string, changed bool) string {
	return resolveGenArtifactPath(out, path, changed)
}

// groupVarsBaseDir picks where copyMissingGroupVars's group_vars/
// subdirectory lives: right next to the generated inventory, so
// `--out someplace/inventory.yml` yields a self-contained
// someplace/{inventory.yml,group_vars/} bundle instead of always
// writing to ./group_vars regardless of --out (handy for keeping
// multiple environments' generated output side by side, e.g.
// `--out envs/staging/inventory.yml`). `--out -`/"" (stdout) has no
// directory of its own, so it falls back to the current directory —
// the same place `pilot inventory lint`/manual `cp` already assume.
func groupVarsBaseDir(out string) string {
	if out == "" || out == "-" {
		return "."
	}
	return filepath.Dir(out)
}

// copyMissingGroupVars backfills <baseDir>/group_vars/<stem>.yml from
// ./group_vars/<stem>.example.yml for every stem actually used by the
// generated inventory — but ONLY when the destination doesn't already
// exist, so it never clobbers settings someone already filled in. A
// stem with no matching example (e.g. "docker", which has no
// group_vars of its own) is silently skipped: existence-checking the
// example file, rather than hand-maintaining a "these roles have no
// group_vars" list, means a future role that gains a group_vars
// example gets picked up here for free.
//
// The SOURCE example always reads from ./group_vars (relative to the
// process's own CWD) — that's the one fixed place the shipped
// .example.yml files actually live, whether that CWD is a local repo
// checkout or /pilot inside the Docker image; it has nothing to do
// with baseDir. Only the DESTINATION follows baseDir, so a bundle
// generated with `--out envs/staging/inventory.yml` gets its
// group_vars written to envs/staging/group_vars/, not scattered back
// into the shipped example directory.
func copyMissingGroupVars(w io.Writer, baseDir string, stems []string) {
	for _, stem := range stems {
		src := filepath.Join("group_vars", stem+".example.yml")
		dst := filepath.Join(baseDir, "group_vars", stem+".yml")

		data, err := os.ReadFile(src)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // role has no group_vars of its own
			}
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}

		if _, err := os.Stat(dst); err == nil {
			fmt.Fprintf(w, "group_vars: %s already exists, left untouched\n", dst)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}
		fmt.Fprintf(w, "group_vars: copied %s -> %s\n", src, dst)
	}
}

// nestedGroupVarsExample is a group_vars example that lives outside the
// flat "<stem>.example.yml" convention copyMissingGroupVars/scanGroupVars
// handle. Currently just dns_zones (group_vars/dns/zones.example.yaml) —
// the repo's own .gitignore (`/group_vars/dns/*.yaml`, tracking only the
// .example.yaml) treats real dns zone files as deliberately separate from
// the templated per-role scaffold, so this only makes the example
// discoverable/copyable through `pilot inventory generate` and `pilot
// edit`'s file picker (see pushGroupVarsFilePicker) — editing its contents
// is still hand-edit-only: dns_zones is a 2-level nested list-of-maps
// (zones, each optionally containing a nested records list), a shape no
// generic small editor in this wizard fits.
type nestedGroupVarsExample struct {
	Role       string // role that implies this example is relevant
	ExampleRel string // relative to the fixed group_vars/ example dir
	DestRel    string // relative to <workspace>/group_vars
}

var nestedGroupVarsExamples = []nestedGroupVarsExample{
	{Role: "dns", ExampleRel: filepath.Join("dns", "zones.example.yaml"), DestRel: filepath.Join("dns", "zones.yaml")},
}

// copyMissingNestedGroupVarsExamples backfills each nestedGroupVarsExample
// whose Role is actually used, mirroring copyMissingGroupVars' stat-then-
// skip idempotency exactly — only ever writes when the destination is
// missing, never overwrites.
func copyMissingNestedGroupVarsExamples(w io.Writer, baseDir string, roles []string) {
	used := make(map[string]bool, len(roles))
	for _, r := range roles {
		used[r] = true
	}
	for _, ex := range nestedGroupVarsExamples {
		if !used[ex.Role] {
			continue
		}
		src := filepath.Join("group_vars", ex.ExampleRel)
		dst := filepath.Join(baseDir, "group_vars", ex.DestRel)

		data, err := os.ReadFile(src)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}

		if _, err := os.Stat(dst); err == nil {
			fmt.Fprintf(w, "group_vars: %s already exists, left untouched\n", dst)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			fmt.Fprintf(w, "group_vars: skip %s (%v)\n", dst, err)
			continue
		}
		fmt.Fprintf(w, "group_vars: copied %s -> %s\n", src, dst)
	}
}

func writeMissingVaultSkeleton(w io.Writer, dst string, hf *inventory.HostsFile) {
	rendered := inventory.GenerateVaultSkeleton(hf)
	if rendered == "" {
		return
	}

	if _, err := os.Stat(dst); err == nil {
		fmt.Fprintf(w, "vault: %s already exists, left untouched\n", dst)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(w, "vault: skip %s (%v)\n", dst, err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		fmt.Fprintf(w, "vault: skip %s (%v)\n", dst, err)
		return
	}
	if err := os.WriteFile(dst, []byte(rendered), 0o600); err != nil {
		fmt.Fprintf(w, "vault: skip %s (%v)\n", dst, err)
		return
	}
	fmt.Fprintf(w, "vault: wrote %s\n", dst)
}

// writeMissingHostVarsSkeleton scaffolds host_vars/<host>.yml for every host
// whose roles have a var with no safe cross-host default (e.g.
// prometheus_site_label) — same stat-then-skip, only-write-when-missing
// semantics as writeMissingVaultSkeleton, one file per host instead of one
// shared file.
func writeMissingHostVarsSkeleton(w io.Writer, dir string, hf *inventory.HostsFile) {
	for _, h := range hf.Hosts {
		rendered, ok := inventory.GenerateHostVarsSkeleton(h)
		if !ok {
			continue
		}
		dst := filepath.Join(dir, "host_vars", h.Name+".yml")

		if _, err := os.Stat(dst); err == nil {
			fmt.Fprintf(w, "host_vars: %s already exists, left untouched\n", dst)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(w, "host_vars: skip %s (%v)\n", dst, err)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fmt.Fprintf(w, "host_vars: skip %s (%v)\n", dst, err)
			continue
		}
		if err := os.WriteFile(dst, []byte(rendered), 0o644); err != nil {
			fmt.Fprintf(w, "host_vars: skip %s (%v)\n", dst, err)
			continue
		}
		fmt.Fprintf(w, "host_vars: wrote %s\n", dst)
	}
}

// resolveRosterPath resolves a freeipa_roster_file value the same way a
// human editing hosts.yml inside a workspace would expect: an absolute path
// is used as-is, a relative one is relative to that workspace's own
// directory (dir), not the pilot process's current working directory.
func resolveRosterPath(dir, rosterPath string) string {
	if rosterPath == "" || filepath.IsAbs(rosterPath) {
		return rosterPath
	}
	return filepath.Join(dir, rosterPath)
}

// writeMissingNFSRosterEntries auto-completes a missing nfs.servers entry
// in the freeipa-identity roster for every host carrying freeipa-nfs-server
// and a non-empty freeipa_roster_file extra var — the one requirement in
// this generator that's safe to fully write for real rather than only
// scaffold, since the NFS service principal is fully derived from data
// pilot already has (see inventory.AppendMissingNFSServerStub). A roster
// that can't be inspected (missing, unparseable, or ansible-vault
// encrypted) is reported and skipped, never treated as an error worth
// failing generation over.
func writeMissingNFSRosterEntries(w io.Writer, dir string, hf *inventory.HostsFile) {
	for _, h := range hf.Hosts {
		if !hasRole(h.Roles, "freeipa-nfs-server") {
			continue
		}
		rosterPath := resolveRosterPath(dir, h.Extra["freeipa_roster_file"])
		if rosterPath == "" {
			continue
		}

		appended, err := inventory.AppendMissingNFSServerStub(rosterPath, h.Name)
		switch {
		case err != nil:
			fmt.Fprintf(w, "nfs roster: skip %s for %s (%v)\n", rosterPath, h.Name, err)
		case appended:
			fmt.Fprintf(w, "nfs roster: appended nfs.servers entry for %s to %s\n", h.Name, rosterPath)
		default:
			fmt.Fprintf(w, "nfs roster: %s already has an entry for %s\n", rosterPath, h.Name)
		}
	}
}

var inventoryLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Validate a simple hosts source file without generating anything",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(invLintIn)
		if err != nil {
			return fmt.Errorf("read %s: %w", invLintIn, err)
		}
		hf, err := inventory.Parse(data)
		if err != nil {
			return err
		}
		issues := inventory.Lint(hf)
		if len(issues) == 0 {
			fmt.Println("ok: no issues found")
			return nil
		}
		for _, i := range issues {
			fmt.Println(i.String())
		}
		if inventory.HasErrors(issues) {
			return fmt.Errorf("%d issue(s) found", len(issues))
		}
		return nil
	},
}

var inventoryRolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "List the valid `roles:` values for a hosts source file",
	Run: func(cmd *cobra.Command, args []string) {
		for _, r := range inventory.Roles() {
			fmt.Printf("%-24s %s\n", r.Name, r.Description)
		}
	},
}

func init() {
	inventoryGenerateCmd.Flags().StringVar(&invGenDir, "dir", ".", "要讀寫哪個資料夾底下的 hosts.yml/inventory.yml/group_vars/(預設目前資料夾；同時指定 --in/--out 時以 --in/--out 為準，跟 pilot edit --dir 相同的概念)")
	inventoryGenerateCmd.Flags().StringVar(&invGenIn, "in", "hosts.yml", "path to the simple hosts source file (relative to --dir unless this flag is set explicitly)")
	inventoryGenerateCmd.Flags().StringVar(&invGenOut, "out", "inventory.yml", "path to write the generated inventory (relative to --dir unless this flag is set explicitly; - for stdout)")
	inventoryGenerateCmd.Flags().BoolVar(&invGenNoGroupVars, "no-group-vars", false, "skip backfilling group_vars/<role>.yml from group_vars/<role>.example.yml for roles actually used (default: backfill missing files, never overwrite existing ones)")
	inventoryGenerateCmd.Flags().BoolVar(&invGenNoVault, "no-vault", false, "skip generating .vault/main.yaml from the roles actually used (default: write only when missing, never overwrite existing files)")
	inventoryGenerateCmd.Flags().StringVar(&invGenVaultOut, "vault-out", ".vault/main.yaml", "path to write the generated plaintext vault skeleton (relative to --dir unless this flag is set explicitly)")
	inventoryGenerateCmd.Flags().BoolVar(&invGenNoHostVars, "no-host-vars", false, "skip scaffolding host_vars/<host>.yml for hosts whose roles have no safe cross-host default, e.g. prometheus_site_label (default: write only when missing, never overwrite existing files)")
	inventoryGenerateCmd.Flags().BoolVar(&invGenNoNFSRoster, "no-nfs-roster", false, "skip auto-completing a missing nfs.servers roster entry for hosts with the freeipa-nfs-server role (default: append only when missing, never touch an existing entry)")
	inventoryLintCmd.Flags().StringVar(&invLintIn, "in", "hosts.yml", "path to the simple hosts source file")

	inventoryCmd.AddCommand(inventoryGenerateCmd)
	inventoryCmd.AddCommand(inventoryLintCmd)
	inventoryCmd.AddCommand(inventoryRolesCmd)
	rootCmd.AddCommand(inventoryCmd)
}
