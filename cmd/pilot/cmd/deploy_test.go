package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
)

// repoRootForTest walks up from the current package directory until it
// finds go.mod. Tests run with cwd == the package's source directory,
// so deployCatalog's playbook paths (repo-root-relative) need this to
// actually stat the files on disk.
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) above " + dir)
		}
		dir = parent
	}
}

func TestPrepareDeployAnsibleRuntimeKeepsControllerArtifactsInDataDir(t *testing.T) {
	dataDir := t.TempDir()
	runtime, err := prepareDeployAnsibleRuntime(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{
		"ansible/home",
		"ansible/tmp",
		"ansible/fact-cache",
		"ansible/ssh-control",
	} {
		if info, err := os.Stat(filepath.Join(dataDir, relative)); err != nil || !info.IsDir() {
			t.Fatalf("runtime directory %s: info=%v err=%v", relative, info, err)
		}
	}
	joined := strings.Join(runtime.Env, "\n")
	for _, want := range []string{
		"ANSIBLE_HOME=" + filepath.Join(dataDir, "ansible", "home"),
		"ANSIBLE_LOCAL_TEMP=" + filepath.Join(dataDir, "ansible", "tmp"),
		"ANSIBLE_CACHE_PLUGIN=jsonfile",
		"ANSIBLE_CACHE_PLUGIN_CONNECTION=" + filepath.Join(dataDir, "ansible", "fact-cache"),
		"ANSIBLE_LOG_PATH=" + filepath.Join(dataDir, "ansible", "ansible.log"),
		"ANSIBLE_SSH_ARGS=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("runtime environment missing %q:\n%s", want, joined)
		}
	}
}

func TestDeployAnsibleCommandUsesRuntimeEnvironment(t *testing.T) {
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := withDeployAnsibleRuntime(context.Background(), runtime)
	cmd := deployAnsibleCommand(ctx, "sh", "-c", "printf %s \"$ANSIBLE_LOCAL_TEMP\"")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(output), runtime.TempDir; got != want {
		t.Fatalf("ANSIBLE_LOCAL_TEMP = %q, want %q", got, want)
	}
}

func TestContractMenuAndActionPlanFailClosed(t *testing.T) {
	upgrade := "playbooks/apply/worker-upgrade.yml"
	catalog, err := contract.NewCatalog([]contract.Contract{{
		ID: "worker", Role: "workers", Playbooks: contract.Playbooks{Apply: "playbooks/apply/worker.yml", Upgrade: &upgrade},
		Dependencies: []contract.Dependency{{Component: "provider", Required: true, Relation: "providerEndpoint"}},
	}, {ID: "provider", Role: "providers", Playbooks: contract.Playbooks{Apply: "playbooks/apply/provider.yml"}}})
	if err != nil {
		t.Fatal(err)
	}
	entry := deployPlaybook{Key: "worker", Label: "Worker"}
	if got := deployMenuLabel(entry, catalog); !strings.Contains(got, "worker (role=workers)") {
		t.Fatalf("menu label = %q", got)
	}
	var out bytes.Buffer
	if err := showContractActionPlan(&out, catalog, []string{"worker"}, "apply"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Contract plan: worker", "provider (providerEndpoint)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("plan missing %q: %s", want, out.String())
		}
	}
	if err := showContractActionPlan(&out, catalog, []string{"provider"}, "upgrade"); err == nil {
		t.Fatal("provider upgrade without a declared playbook must fail closed")
	}
	if got, err := selectedActionPlaybook(catalog, []string{"worker"}, "upgrade"); err != nil || got != upgrade {
		t.Fatalf("upgrade playbook=%q err=%v", got, err)
	}
	if _, err := selectedActionPlaybook(catalog, []string{"provider"}, "upgrade"); err == nil {
		t.Fatal("upgrade without a declared playbook must fail closed")
	}
}

func TestDeployEntryExperimentalAndDependencyOrder(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "client", Role: "client", Dependencies: []contract.Dependency{{Component: "provider", Required: true}}},
		{ID: "provider", Role: "provider"},
		{ID: "experimental", Role: "lab", Experimental: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deployEntryExperimental(deployPlaybook{Key: "experimental"}, catalog) {
		t.Fatal("experimental entry was not recognized")
	}
	plan, err := delivery.PlanComponents(catalog, []string{"client"}, false)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	showComponentDeploymentOrder(&out, plan)
	if !strings.Contains(out.String(), "provider[provider] → client[client]") {
		t.Fatalf("order view = %q", out.String())
	}
}

func TestReconcileCatalogIsExplicitAndContractBacked(t *testing.T) {
	root := repoRootForTest(t)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range deployCatalog {
		if !entry.Reconcile {
			continue
		}
		got = append(got, entry.Key)
		component, ok := catalog.Component(entry.Key)
		if !ok {
			t.Errorf("reconcile entry %q has no contract", entry.Key)
			continue
		}
		if component.Playbooks.Apply != entry.Playbook {
			t.Errorf("reconcile entry %q playbook=%q, contract apply=%q", entry.Key, entry.Playbook, component.Playbooks.Apply)
		}
	}
	if want := []string{"freeipa-identity"}; !slices.Equal(got, want) {
		t.Fatalf("reconcile entries = %v, want %v; future nginx config must not be exposed before its contract and playbook exist", got, want)
	}
}

// TestDumpMenuDebug covers the PILOT_DEBUG_MENU=1 escape hatch used by
// trec-scripted runs to read a promptui.Select menu's real, live item
// list (and 0-based DOWN <n> index) from the recorded terminal output,
// instead of recomputing it from source or eyeballing the rendered
// screen — see .agents/skills/pilot-trec-verification/SKILL.md §2.
func TestDumpMenuDebug(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	dumpMenuDebug("測試選單", []string{"item-a", "item-b"})
	w.Close()
	os.Stderr = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"測試選單", "2 項", "0: item-a", "1: item-b"} {
		if !strings.Contains(got, want) {
			t.Errorf("dumpMenuDebug output missing %q; got:\n%s", want, got)
		}
	}
}

func TestDeployCatalog_PlaybooksExistAndAreWellFormed(t *testing.T) {
	root := repoRootForTest(t)
	seen := map[string]bool{}
	for _, p := range deployCatalog {
		if p.Key == "" {
			t.Fatalf("catalog entry %q has an empty Key", p.Label)
		}
		if seen[p.Key] {
			t.Fatalf("duplicate catalog Key %q", p.Key)
		}
		seen[p.Key] = true

		if p.StageVar != "stage" && p.StageVar != "patch_stage" {
			t.Fatalf("%s: StageVar must be \"stage\" or \"patch_stage\", got %q", p.Key, p.StageVar)
		}

		full := filepath.Join(root, p.Playbook)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("%s: playbook %s does not exist: %v", p.Key, p.Playbook, err)
		}
	}
	// AGENTS.md §4.3 tracks this count; keep the two in sync deliberately
	// rather than silently drifting.
	if len(deployCatalog) != 23 {
		t.Fatalf("expected 23 apply playbooks in the catalog (see AGENTS.md §4.3), got %d", len(deployCatalog))
	}
}

func TestNFSSiteDeploymentProjection(t *testing.T) {
	root := repoRootForTest(t)
	data, err := os.ReadFile(filepath.Join(root, "playbooks", "site.yml"))
	if err != nil {
		t.Fatal(err)
	}
	site := string(data)
	for _, want := range []string{
		"import_playbook: apply/freeipa-nfs-server-apply.yml",
		"tags: [freeipa, freeipa-nfs-server]",
		"import_playbook: apply/freeipa-nfs-client-apply.yml",
		"tags: [freeipa, freeipa-nfs-client]",
	} {
		if !strings.Contains(site, want) {
			t.Errorf("site.yml missing NFS deployment projection %q", want)
		}
	}

	serverPos := strings.Index(site, "apply/freeipa-nfs-server-apply.yml")
	clientPos := strings.Index(site, "apply/freeipa-nfs-client-apply.yml")
	if !(strings.Index(site, "apply/freeipa-server-apply.yml") < serverPos && serverPos < strings.Index(site, "apply/freeipa-client-apply.yml") && strings.Index(site, "apply/freeipa-client-apply.yml") < clientPos) {
		t.Error("site.yml must deploy FreeIPA server, NFS server, FreeIPA client, then NFS clients")
	}

	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	components, err := componentsForPlaybook(catalog, "playbooks/site.yml", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"freeipa-nfs-server", "freeipa-nfs-client"} {
		if !slices.Contains(components, want) {
			t.Errorf("full-site deployment contracts omit %q: %v", want, components)
		}
	}
}

func TestValidateOptionalKV(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"  ", false},
		{"a=b", false},
		{"a=b c=d", false},
		{"a=b  c=d", false},
		{"noequals", true},
		{"a=b bad", true},
	}
	for _, c := range cases {
		err := validateOptionalKV(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateOptionalKV(%q) error=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestValidateHoursWithinWeek(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"0", false},
		{"168", false},
		{"169", true},
		{"-1", true},
		{"abc", true},
	}
	for _, c := range cases {
		err := validateHoursWithinWeek(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateHoursWithinWeek(%q) error=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestValidateFileExists(t *testing.T) {
	root := repoRootForTest(t)
	if err := validateFileExists(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("expected go.mod to exist: %v", err)
	}
	if err := validateFileExists(""); err == nil {
		t.Error("expected error for empty path")
	}
	if err := validateFileExists("/does/not/exist/nope"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseDeployTimeout(t *testing.T) {
	got, err := parseDeployTimeout("30m")
	if err != nil {
		t.Fatalf("unexpected error for default value: %v", err)
	}
	if got != 30*time.Minute {
		t.Errorf("got %v, want 30m", got)
	}

	got, err = parseDeployTimeout("1h30m")
	if err != nil {
		t.Fatalf("unexpected error for 1h30m: %v", err)
	}
	if got != 90*time.Minute {
		t.Errorf("got %v, want 1h30m", got)
	}

	for _, bad := range []string{"", "notaduration", "30", "-30m", "0m", "0"} {
		if _, err := parseDeployTimeout(bad); err == nil {
			t.Errorf("parseDeployTimeout(%q): expected error, got nil", bad)
		}
	}
}

func TestIsVaultEncrypted(t *testing.T) {
	dir := t.TempDir()

	encrypted := filepath.Join(dir, "encrypted.yaml")
	if err := os.WriteFile(encrypted, []byte("$ANSIBLE_VAULT;1.1;AES256\n62353933...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isVaultEncrypted(encrypted) {
		t.Error("expected an ansible-vault header to be detected as encrypted")
	}

	plaintext := filepath.Join(dir, "plaintext.yaml")
	if err := os.WriteFile(plaintext, []byte("ipa_admin_password: hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if isVaultEncrypted(plaintext) {
		t.Error("expected plaintext YAML to not be detected as encrypted")
	}

	if isVaultEncrypted(filepath.Join(dir, "does-not-exist.yaml")) {
		t.Error("expected a missing file to not be detected as encrypted")
	}
}

func TestParseGroupHostFromInventoryList(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		group    string
		wantHost string
		wantOK   bool
	}{
		{
			name: "resolves ansible_host over the bare hostname",
			json: `{
				"seaweedfs-s3": {"hosts": ["it-service"]},
				"_meta": {"hostvars": {"it-service": {"ansible_host": "10.1.58.12"}}}
			}`,
			group:    "seaweedfs-s3",
			wantHost: "10.1.58.12",
			wantOK:   true,
		},
		{
			name: "falls back to the inventory hostname with no ansible_host",
			json: `{
				"seaweedfs-s3": {"hosts": ["s3-gateway"]},
				"_meta": {"hostvars": {"s3-gateway": {}}}
			}`,
			group:    "seaweedfs-s3",
			wantHost: "s3-gateway",
			wantOK:   true,
		},
		{
			name: "resolves a different group name",
			json: `{
				"wazuh-manager": {"hosts": ["wazuh-mgr"]},
				"seaweedfs-s3": {"hosts": ["it-service"]},
				"_meta": {"hostvars": {"wazuh-mgr": {"ansible_host": "10.1.58.20"}, "it-service": {"ansible_host": "10.1.58.12"}}}
			}`,
			group:    "wazuh-manager",
			wantHost: "10.1.58.20",
			wantOK:   true,
		},
		{
			name:     "group absent",
			json:     `{"_meta": {"hostvars": {}}}`,
			group:    "seaweedfs-s3",
			wantHost: "",
			wantOK:   false,
		},
		{
			name:     "group present but empty",
			json:     `{"seaweedfs-s3": {"hosts": []}, "_meta": {"hostvars": {}}}`,
			group:    "seaweedfs-s3",
			wantHost: "",
			wantOK:   false,
		},
		{
			name:     "unparseable JSON",
			json:     `not json`,
			group:    "seaweedfs-s3",
			wantHost: "",
			wantOK:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, ok := parseGroupHostFromInventoryList(c.json, c.group)
			if host != c.wantHost || ok != c.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", host, ok, c.wantHost, c.wantOK)
			}
		})
	}
}

func TestDefaultVaultFile(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := defaultVaultFile(inv); got != "" {
		t.Errorf("expected no vault file detected yet, got %q", got)
	}

	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	vaultFile := filepath.Join(vaultDir, "main.yaml")
	if err := os.WriteFile(vaultFile, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := defaultVaultFile(inv); got != vaultFile {
		t.Errorf("expected %q, got %q", vaultFile, got)
	}
}

func TestSiteAutoHostVars_DedupesByVar(t *testing.T) {
	avs := siteAutoHostVars()

	seen := make(map[string]string) // var -> group
	for _, av := range avs {
		if g, dup := seen[av.Var]; dup {
			t.Errorf("var %q appears twice (groups %q and %q)", av.Var, g, av.Group)
		}
		seen[av.Var] = av.Group
	}

	// The site-wide flow must cover every var any catalog entry can
	// auto-detect — a var reachable from the single-component wizard but
	// missing here reintroduces the pre-2026-07-17 site-deploy gap.
	for _, p := range deployCatalog {
		for _, av := range p.AutoHostVars {
			if g, ok := seen[av.Var]; !ok {
				t.Errorf("catalog var %q (component %s) missing from siteAutoHostVars", av.Var, p.Key)
			} else if g != av.Group {
				t.Errorf("var %q resolves group %q site-wide but %q under component %s", av.Var, g, av.Group, p.Key)
			}
		}
	}
}
