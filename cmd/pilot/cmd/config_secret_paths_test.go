package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/vaultfile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConfigSecretPaths_EditorEntrypoints(t *testing.T) {
	for _, editor := range []struct {
		name string
		open func(*editRouterModel, string, string) tea.Cmd
	}{
		{"vault", pushVaultOpen},
		{"snmp", pushSNMPCredentialOpen},
		{"roster", func(r *editRouterModel, dir, path string) tea.Cmd { return pushRosterManager(r, dir, path, "") }},
		{"roster_create", func(r *editRouterModel, dir, path string) tea.Cmd {
			return pushRosterCreateWithPassword(r, dir, path, "DUMMY130_PASSWORD", "")
		}},
		{"encrypted_editor", pushAnsibleVaultShellout},
	} {
		for _, form := range []string{"group_vars", "host_vars", "symlink", "external_vars", "hardlink"} {
			t.Run(editor.name+"/"+form, func(t *testing.T) {
				dir := t.TempDir()
				r := newEditRouterModel(dir)
				path := filepath.Join(dir, "group_vars", "all.yml")
				switch form {
				case "host_vars":
					path = filepath.Join(dir, "host_vars", "all.yml")
				case "external_vars":
					path = filepath.Join(t.TempDir(), "group_vars", "all.yml")
				case "symlink":
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Dir(path), filepath.Join(dir, "alias")); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(dir, "alias", "all.yml")
				case "hardlink":
					writeTestFile(t, path, "port: 8080\n")
					alias := filepath.Join(dir, "safe-looking.yaml")
					if err := os.Link(path, alias); err != nil {
						t.Fatal(err)
					}
					path = alias
				}
				editor.open(&r, dir, path)
				if r.err == nil {
					t.Fatal("secret editor accepted an inventory vars destination")
				}
				if strings.Contains(r.err.Error(), "DUMMY130") {
					t.Fatal("error leaked credential")
				}
				if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), "DUMMY130") {
					t.Fatal("credential was persisted")
				}
			})
		}
	}
}

func TestConfigSecretPaths_SaveRechecksDestination(t *testing.T) {
	for _, kind := range []string{"vault", "snmp"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "safe.yaml")
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			var choose func() error
			if kind == "vault" {
				doc, err := vaultfile.Parse([]byte("password: DUMMY130_PASSWORD\n"))
				if err != nil {
					t.Fatal(err)
				}
				pushVaultEditorScreen(&r, dir, path, doc, true, "")
				choose = func() error { return d.choose(&r, "存檔並離開") }
			} else {
				doc, err := monitoring.LoadSNMPCredentialDoc(path)
				if err != nil {
					t.Fatal(err)
				}
				doc.Set("switch", monitoring.SNMPCredentialFields{"community": "DUMMY130_PASSWORD"})
				pushSNMPCredentialsEditor(&r, dir, path, doc, "")
				choose = func() error { return d.chooseByID(&r, "mon.snmp.cred.editor", "mon.snmp.cred.editor.save") }
			}
			target := filepath.Join(dir, "group_vars", "all.yml")
			writeTestFile(t, target, "port: 8080\n")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			_ = choose()
			if r.err == nil {
				t.Fatal("save did not reject changed destination")
			}
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "port: 8080\n" {
				t.Fatal("save changed forbidden destination")
			}
		})
	}
}

func TestConfigSecretPaths_SaveRechecksReverseDirectoryAlias(t *testing.T) {
	for _, kind := range []string{"vault", "snmp"} {
		for _, tree := range []string{"group_vars", "host_vars"} {
			for _, existing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/existing=%v", kind, tree, existing), func(t *testing.T) {
					dir, external := t.TempDir(), t.TempDir()
					path := filepath.Join(external, "all.yml")
					const original = "port: 8080\n"
					if existing {
						writeTestFile(t, path, original)
					}
					r := newEditRouterModel(dir)
					d := automationDriver{dir: dir}
					var save func() error
					if kind == "vault" {
						doc, err := vaultfile.Parse([]byte("password: DUMMY130_PASSWORD\n"))
						if err != nil {
							t.Fatal(err)
						}
						pushVaultEditorScreen(&r, dir, path, doc, true, "")
						save = func() error { return d.choose(&r, "存檔並離開") }
					} else {
						doc, err := monitoring.LoadSNMPCredentialDoc(path)
						if err != nil {
							t.Fatal(err)
						}
						doc.Set("switch", monitoring.SNMPCredentialFields{"community": "DUMMY130_PASSWORD"})
						pushSNMPCredentialsEditor(&r, dir, path, doc, "")
						save = func() error { return d.chooseByID(&r, "mon.snmp.cred.editor", "mon.snmp.cred.editor.save") }
					}
					if r.err != nil {
						t.Fatalf("opening external editor: %v", r.err)
					}
					if err := os.Symlink(external, filepath.Join(dir, tree)); err != nil {
						t.Fatal(err)
					}
					_ = save()
					if r.err == nil {
						t.Fatal("save accepted external destination after reverse vars alias appeared")
					}
					data, err := os.ReadFile(path)
					if existing {
						if err != nil || string(data) != original {
							t.Fatal("save modified existing forbidden destination")
						}
					} else if !os.IsNotExist(err) {
						t.Fatal("save created forbidden destination")
					}
				})
			}
		}
	}
}

func TestConfigSecretPaths_RosterPasswordSaveRechecksReverseDirectoryAlias(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	pushRosterUserPasswordInitial(&r, dir, path, "alice")
	if err := os.Symlink(filepath.Dir(path), filepath.Join(dir, "host_vars")); err != nil {
		t.Fatal(err)
	}
	if err := d.typeText(&r, "DUMMY130_PASSWORD", true); err != nil {
		t.Fatal(err)
	}
	_ = d.enter(&r)
	if r.err == nil {
		t.Fatal("roster password save accepted reverse vars alias")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(original) {
		t.Fatal("roster password save modified forbidden destination")
	}
}

func TestConfigSecretPaths_ExternalRosterMutationRechecksWorkspace(t *testing.T) {
	// Keep cwd outside both independent temporary directories. Persistence
	// helpers that only validate "." cannot discover the selected workspace.
	for _, mutation := range []struct {
		name   string
		open   func(*editRouterModel, string, string) tea.Cmd
		submit func(*automationDriver, *editRouterModel) error
	}{
		{"password", func(r *editRouterModel, dir, path string) tea.Cmd {
			return pushRosterUserPasswordInitial(r, dir, path, "alice")
		}, func(d *automationDriver, r *editRouterModel) error {
			if err := d.typeText(r, "DUMMY130_PASSWORD", true); err != nil {
				return err
			}
			return d.enter(r)
		}},
		{"group", func(r *editRouterModel, dir, path string) tea.Cmd {
			return pushRosterGroupTextField(r, dir, path, "team-x", "description", "description", "")
		}, func(d *automationDriver, r *editRouterModel) error {
			if err := d.typeText(r, "updated", true); err != nil {
				return err
			}
			return d.enter(r)
		}},
		{"hbac", func(r *editRouterModel, dir, path string) tea.Cmd { return pushRosterHostAccessMenu(r, dir, path, "") }, func(d *automationDriver, r *editRouterModel) error {
			return d.chooseByID(r, "roster.access.top", "roster.access.top.disable_allow_all")
		}},
		{"hostgroup", pushRosterAddHostgroup, func(d *automationDriver, r *editRouterModel) error {
			if err := d.typeText(r, "new-hg", true); err != nil {
				return err
			}
			return d.enter(r)
		}},
		{"sudo", func(r *editRouterModel, dir, path string) tea.Cmd {
			return pushRosterAddSudoCommandGroupCommands(r, dir, path, "new-commands")
		}, func(d *automationDriver, r *editRouterModel) error {
			if err := d.typeText(r, "/usr/bin/id", true); err != nil {
				return err
			}
			return d.enter(r)
		}},
		{"identity_policy", func(r *editRouterModel, dir, path string) tea.Cmd {
			return pushRosterAddPasswordPolicyPriority(r, dir, path, "new-policy", "role-y")
		}, func(d *automationDriver, r *editRouterModel) error {
			if err := d.typeText(r, "10", true); err != nil {
				return err
			}
			return d.enter(r)
		}},
	} {
		for _, tree := range []string{"", "group_vars", "host_vars"} {
			t.Run(mutation.name+"/"+tree, func(t *testing.T) {
				dir, fixture := writeHBACPolicyRosterFixture(t)
				original, err := os.ReadFile(fixture)
				if err != nil {
					t.Fatal(err)
				}
				external := t.TempDir()
				path := filepath.Join(external, "roster.yml")
				writeTestFile(t, path, string(original))
				r := newEditRouterModel(dir)
				d := automationDriver{dir: dir}
				mutation.open(&r, dir, path)
				if r.err != nil {
					t.Fatalf("opening external roster: %v", r.err)
				}
				if tree != "" {
					if err := os.Symlink(external, filepath.Join(dir, tree)); err != nil {
						t.Fatal(err)
					}
				}
				submitErr := mutation.submit(&d, &r)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if tree == "" {
					if submitErr != nil || r.err != nil {
						t.Fatalf("legitimate external mutation rejected: submit=%v router=%v", submitErr, r.err)
					}
					if string(data) == string(original) {
						t.Fatal("legitimate external mutation was not persisted")
					}
				} else {
					if r.err == nil || !strings.Contains(r.err.Error(), "outside group_vars/") {
						t.Fatalf("workspace alias was not rejected: submit=%v router=%v", submitErr, r.err)
					}
					if string(data) != string(original) {
						t.Fatal("external roster mutation changed forbidden destination")
					}
				}
			})
		}
	}
}

func TestConfigSecretPaths_ExternalRosterAutofixRechecksWorkspace(t *testing.T) {
	for _, kind := range []string{"nfs_bootstrap", "nfs_autofix", "inventory_generate", "migration_banner", "client_autofill", "deploy_migration", "deploy_client_autofill"} {
		for _, tree := range []string{"", "group_vars", "host_vars"} {
			t.Run(kind+"/"+tree, func(t *testing.T) {
				dir, external := t.TempDir(), t.TempDir()
				path := filepath.Join(external, "roster.yml")
				const original = "schema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\n  admin: {principal: admin, password: DUMMY130_PASSWORD}\nusers: []\n"
				writeTestFile(t, path, original)
				writeTestFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  web1:\n    ansible_host: 192.0.2.1\n    roles: [freeipa-client]\n")
				h := inventory.Host{Name: "nfs-demo", Roles: []string{"freeipa-nfs-server"}, Extra: map[string]string{"freeipa_roster_file": path}}
				hf := &inventory.HostsFile{Hosts: []inventory.Host{h}}
				r := newEditRouterModel(dir)
				if r.err != nil {
					t.Fatal(r.err)
				}
				if tree != "" {
					if err := os.Symlink(external, filepath.Join(dir, tree)); err != nil {
						t.Fatal(err)
					}
				}
				switch kind {
				case "nfs_bootstrap":
					pushNFSRoleBootstrap(&r, dir, filepath.Join(dir, "hosts.yml"), hf, h.Name, nil)
				case "nfs_autofix":
					autofixNFSRosterEntry(dir, h)
				case "inventory_generate":
					writeMissingNFSRosterEntries(io.Discard, dir, hf)
				case "migration_banner":
					ensureRosterSchemaCurrentBanner(dir, path)
				case "client_autofill":
					autoFillFreeIPAClientRosterHostsBanner(dir, path)
				case "deploy_migration":
					err := ensureFreeIPARostersCurrentSnapshot(io.Discard, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{Groups: map[string][]string{"freeipa-server": {"ipa"}}, HostVars: map[string]map[string]any{"ipa": {"freeipa_roster_file": path}}})
					if err != nil {
						t.Fatal(err)
					}
				case "deploy_client_autofill":
					err := autoFillFreeIPAClientHostsIntoRoster(context.Background(), io.Discard, []contract.Contract{{ID: "freeipa-client", Role: "freeipa-client"}}, filepath.Join(dir, "inventory.yml"), []string{"freeipa_roster_file=" + path}, vaultInput{})
					if err != nil {
						t.Fatal(err)
					}
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				// Check all siblings too: migration backup names use a schema
				// timestamp suffix, and no secret copy may appear on rejection.
				entries, err := os.ReadDir(external)
				if err != nil {
					t.Fatal(err)
				}
				if tree == "" {
					if string(data) == original {
						t.Fatal("legitimate external autofix did not update roster")
					}
				} else if string(data) != original || len(entries) != 1 {
					t.Fatal("forbidden autofix changed roster or created a secret-bearing backup")
				}
			})
		}
	}
}

func TestConfigSecretPaths_DefaultVaultSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "group_vars"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "group_vars"), filepath.Join(dir, ".vault")); err != nil {
		t.Fatal(err)
	}
	if validateInventorySecretStorage(dir) == nil {
		t.Fatal("default .vault target can enter vars tree")
	}
}

func TestConfigSecretPaths_RosterDoesNotMigrateVarsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_vars", "all.yml")
	const original = "schema_version: 1\nfreeipa:\n  admin: {principal: admin, password: ''}\n"
	writeTestFile(t, path, original)
	r := newEditRouterModel(dir)
	pushRosterManager(&r, dir, path, "")
	if r.err == nil {
		t.Fatal("roster auto-migration accepted vars file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatal("roster migration modified vars file before rejection")
	}
}

func TestConfigSecretPaths_InspectUsesSharedMaterialPolicy(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	for _, material := range []string{"-----BEGIN PRIVATE KEY-----DUMMY130", "-----BEGIN PGP PRIVATE KEY BLOCK-----DUMMY130"} {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "group_vars", "thanos-query.yml"), "thanos_query_url: '"+material+"'\n")
		result, out, err := inspectHandler(editMCPToolsOptions{Dir: dir})(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeGroupVars: true})
		data, _ := json.Marshal([]any{result, out, err})
		if strings.Contains(string(data), material) {
			t.Fatal("MCP inspect exported credential material")
		}
		if !out.GroupVarsMetadata["thanos-query.yml"]["thanos_query_url"].Redacted {
			t.Fatal("missing redaction metadata")
		}
	}
}

func TestConfigSecretPaths_ExternalVaultAndSNMPSavesStillWork(t *testing.T) {
	for _, kind := range []string{"vault", "snmp"} {
		t.Run(kind, func(t *testing.T) {
			dir, external := t.TempDir(), t.TempDir()
			path := filepath.Join(external, "secrets.yml")
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			var err error
			if kind == "vault" {
				doc, parseErr := vaultfile.Parse([]byte("password: DUMMY130_PASSWORD\n"))
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				pushVaultEditorScreen(&r, dir, path, doc, true, "")
				err = d.choose(&r, "存檔並離開")
			} else {
				doc, loadErr := monitoring.LoadSNMPCredentialDoc(path)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				doc.Set("switch", monitoring.SNMPCredentialFields{"community": "DUMMY130_PASSWORD"})
				pushSNMPCredentialsEditor(&r, dir, path, doc, "")
				err = d.chooseByID(&r, "mon.snmp.cred.editor", "mon.snmp.cred.editor.save")
			}
			if err != nil || r.err != nil {
				t.Fatalf("save: err=%v router=%v", err, r.err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), "DUMMY130_PASSWORD") {
				t.Fatal("external credential was not saved")
			}
		})
	}
}

func TestConfigSecretPaths_RosterPasswordSaveRechecksDestination(t *testing.T) {
	dir, path := writeHBACPolicyRosterFixture(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	pushRosterUserPasswordInitial(&r, dir, path, "alice")
	target := filepath.Join(dir, "host_vars", "all.yml")
	writeTestFile(t, target, string(original))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := d.typeText(&r, "DUMMY130_PASSWORD", true); err != nil {
		t.Fatal(err)
	}
	_ = d.enter(&r)
	if r.err == nil {
		t.Fatal("roster password callback accepted vars destination")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatal("roster password callback changed vars file")
	}
}

func TestConfigSecretPaths_VaultCreationRechecksDestination(t *testing.T) {
	dir := t.TempDir()
	sourceDir := filepath.Join(dir, "external")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	path := filepath.Join(sourceDir, "new.yml")
	pushVaultOpen(&r, dir, path)
	if err := os.Remove(sourceDir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, sourceDir); err != nil {
		t.Fatal(err)
	}
	_ = d.confirmYesNo(&r, true)
	if r.err == nil {
		t.Fatal("vault creation callback accepted vars destination")
	}
	if _, err := os.Stat(filepath.Join(target, "new.yml")); !os.IsNotExist(err) {
		t.Fatal("vault creation callback wrote vars file")
	}
}
