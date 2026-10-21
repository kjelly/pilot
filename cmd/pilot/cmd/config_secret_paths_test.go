package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
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
			if err := os.Symlink(external, filepath.Join(dir, ".vault")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".vault", "secrets.yml")
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

// Exercise the actual save callbacks with an initially safe path. A different
// process adding a directory alias while a form is open must stop persistence.
func TestConfigSecretPaths_SaveRejectsVarsDirectoryAliasIntroducedWhileOpen(t *testing.T) {
	for _, kind := range []string{"vault", "snmp", "roster"} {
		for _, tree := range []string{"group_vars", "host_vars"} {
			for _, nested := range []bool{false, true} {
				for _, existing := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/nested=%t/existing=%t", kind, tree, nested, existing), func(t *testing.T) {
						dir, external := t.TempDir(), t.TempDir()
						path := filepath.Join(external, "all.yml")
						original := "port: 8080\n"
						if kind == "roster" {
							_, fixture := writeHBACPolicyRosterFixture(t)
							data, err := os.ReadFile(fixture)
							if err != nil {
								t.Fatal(err)
							}
							original = string(data)
						}
						if existing {
							writeTestFile(t, path, original)
						}
						r := newEditRouterModel(dir)
						d := automationDriver{dir: dir}
						var save func() error
						switch kind {
						case "vault":
							doc, err := vaultfile.Parse([]byte("password: DUMMY130_PASSWORD\n"))
							if err != nil {
								t.Fatal(err)
							}
							pushVaultEditorScreen(&r, dir, path, doc, true, "")
							save = func() error { return d.choose(&r, "存檔並離開") }
						case "snmp":
							doc, err := monitoring.LoadSNMPCredentialDoc(path)
							if err != nil {
								t.Fatal(err)
							}
							doc.Set("switch", monitoring.SNMPCredentialFields{"community": "DUMMY130_PASSWORD"})
							pushSNMPCredentialsEditor(&r, dir, path, doc, "")
							save = func() error { return d.chooseByID(&r, "mon.snmp.cred.editor", "mon.snmp.cred.editor.save") }
						case "roster":
							if existing {
								pushRosterUserPasswordInitial(&r, dir, path, "alice")
							} else {
								pushRosterCreatePrompt(&r, dir, path)
							}
							save = func() error {
								if err := d.typeText(&r, "DUMMY130_PASSWORD", true); err != nil {
									return err
								}
								return d.enter(&r)
							}
						}
						if r.err != nil {
							t.Fatalf("open safe editor: %v", r.err)
						}
						alias := filepath.Join(dir, tree)
						if nested {
							alias = filepath.Join(alias, "nested")
						}
						if err := os.MkdirAll(filepath.Dir(alias), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(external, alias); err != nil {
							t.Fatal(err)
						}
						_ = save()
						if r.err == nil {
							t.Error("save accepted vars directory alias")
						}
						data, err := os.ReadFile(path)
						if existing {
							if err != nil {
								t.Fatal(err)
							}
							if string(data) != original {
								t.Error("save changed aliased external file")
							}
						} else if !os.IsNotExist(err) {
							t.Error("save created aliased external file")
						}
						if r.err != nil && strings.Contains(r.err.Error(), "DUMMY130_PASSWORD") {
							t.Error("error leaked credential")
						}
					})
				}
			}
		}
	}
}

func TestConfigSecretPaths_ExternalRosterPasswordSavesStillWork(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			dir, external := t.TempDir(), t.TempDir()
			if err := os.Symlink(external, filepath.Join(dir, ".vault")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".vault", "roster.yml")
			if existing {
				_, fixture := writeHBACPolicyRosterFixture(t)
				data, err := os.ReadFile(fixture)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, path, string(data))
			}
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			if existing {
				pushRosterUserPasswordInitial(&r, dir, path, "alice")
			} else {
				pushRosterCreatePrompt(&r, dir, path)
			}
			if err := d.typeText(&r, "DUMMY130_PASSWORD", true); err != nil {
				t.Fatal(err)
			}
			if err := d.enter(&r); err != nil {
				t.Fatal(err)
			}
			if r.err != nil {
				t.Fatalf("save: %v", r.err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), "DUMMY130_PASSWORD") {
				t.Fatal("external roster credential was not saved")
			}
		})
	}
}
