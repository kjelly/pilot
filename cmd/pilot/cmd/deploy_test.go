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

func TestPromptCatalogBatchInputsCollectsSharedQuestionsOnce(t *testing.T) {
	no := false
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "要限定只套用到某台主機嗎？", Text: "host-a"},
		{Prompt: "要只跑某幾個檢查項目嗎？"},
		{Prompt: "這次佈署需要密碼變數嗎？", Select: "不需要"},
		{Prompt: "這次套用要手動輸入 sudo(become)密碼嗎？", Confirm: &no},
		{Prompt: "還有其他 -e 變數要帶嗎？", Text: "foo=bar"},
	}}
	oldPrompt := activePromptAutomation
	activePromptAutomation = p
	defer func() { activePromptAutomation = oldPrompt }()

	inputs, err := promptCatalogBatchInputs(&bytes.Buffer{}, filepath.Join(t.TempDir(), "inventory.yml"), []deployPlaybook{
		{VaultHint: "first hint"},
		{VaultHint: "first hint"},
		{VaultHint: "second hint"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inputs.limit != "host-a" || inputs.tags != "" {
		t.Fatalf("batch inputs = %+v, want shared limit/tags", inputs)
	}
	if got, want := inputs.extraVars, []string{"foo=bar"}; !slices.Equal(got, want) {
		t.Fatalf("extra vars = %v, want %v", got, want)
	}
	if inputs.vault.AskBecomePass {
		t.Fatal("AskBecomePass = true, want false")
	}
	if len(p.answers) != 0 {
		t.Fatalf("shared prompt answers left unused: %+v", p.answers)
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

func TestDeployInventorySnapshotReusesOneRuntimeBackedInventoryLoadForAutoHosts(t *testing.T) {
	binDir := t.TempDir()
	callsPath := filepath.Join(t.TempDir(), "inventory-calls")
	script := `#!/bin/sh
if [ -z "$ANSIBLE_LOCAL_TEMP" ]; then
  exit 41
fi
printf x >> "$PILOT_TEST_INVENTORY_CALLS"
printf '%s\n' '{"_meta":{"hostvars":{"log-1":{"ansible_host":"10.0.0.10"}}},"all":{"children":["log-server"]},"log-server":{"hosts":["log-1"]}}'
`
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_TEST_INVENTORY_CALLS", callsPath)

	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadDeployInventorySnapshot(withDeployAnsibleRuntime(context.Background(), runtime), "inventory.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := snapshot.Groups["all"], []string{"log-1"}; !slices.Equal(got, want) {
		t.Fatalf("snapshot all hosts = %v, want %v", got, want)
	}
	for _, variable := range []string{"siem_forward_host", "restic_s3_target_host", "loki_target_host"} {
		host, ok := resolveGroupHost(snapshot, "log-server", variable, []string{"audit-log-forwarding"})
		if !ok || host != "10.0.0.10" {
			t.Fatalf("resolveGroupHost(%s) = (%q, %v), want (10.0.0.10, true)", variable, host, ok)
		}
	}
	calls, err := os.ReadFile(callsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(calls); got != "x" {
		t.Fatalf("ansible-inventory calls = %q, want exactly one initial snapshot load", got)
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
	if want := []string{
		"freeipa-identity", "freeipa-dns", "freeipa-dns-client", "freeipa-ca-trust",
		"freeipa-server-replica", "freeipa-realm-replacement", "internal-endpoint", "prometheus",
	}; !slices.Equal(got, want) {
		t.Fatalf("reconcile entries = %v, want %v; a reconcile entry must not be exposed before its contract and playbook exist", got, want)
	}
}

func TestAutoFillMonitoringFiles(t *testing.T) {
	dir := t.TempDir()
	if vars, found, err := autoFillMonitoringFiles(dir); err != nil || found || vars != nil {
		t.Fatalf("missing registry = vars %v found %v err %v", vars, found, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "monitoring"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"targets.yml", "scrape-profiles.yml"} {
		if err := os.WriteFile(filepath.Join(dir, "monitoring", name), []byte("schemaVersion: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vars, found, err := autoFillMonitoringFiles(dir)
	if err != nil || !found || len(vars) != 2 {
		t.Fatalf("registry = vars %v found %v err %v", vars, found, err)
	}
	if !strings.HasPrefix(vars[0], "monitoring_targets_file=/") || !strings.HasPrefix(vars[1], "monitoring_profiles_file=/") {
		t.Fatalf("registry vars are not absolute: %v", vars)
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
	if len(deployCatalog) != 34 {
		t.Fatalf("expected 34 apply playbooks in the catalog (see AGENTS.md §4.3), got %d", len(deployCatalog))
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
	freeIPAClientPos := strings.Index(site, "apply/freeipa-client-apply.yml")
	if !(strings.Index(site, "apply/freeipa-server-apply.yml") < freeIPAClientPos && freeIPAClientPos < serverPos && serverPos < clientPos) {
		t.Error("site.yml must deploy FreeIPA server, enroll FreeIPA clients, then deploy NFS server and NFS clients")
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

// TestFqdnForGroupHost fixes the behavior spec for upgrading a cross-role
// host var from the target's ansible_host IP to its FreeIPA FQDN: it must
// only fire when the target actually has a FreeIPA A record
// (freeipa-client membership) AND every consumer group that will read the
// resulting value can actually resolve it (freeipa-dns-client membership).
// Either check failing must fall back to "" / false so the caller keeps
// using the plain IP — never a guess that could resolve to nothing.
func TestFqdnForGroupHost(t *testing.T) {
	baseJSON := `{
		"log-server": {"hosts": ["log1"]},
		"audit-log-forwarding": {"hosts": ["audit1"]},
		"wazuh-manager": {"hosts": ["wazuh1"]},
		"freeipa-client": {"hosts": ["log1", "audit1", "wazuh1"]},
		"freeipa-dns-client": {"hosts": ["log1", "audit1", "wazuh1"]},
		"_meta": {"hostvars": {
			"log1": {"ansible_host": "10.1.1.1", "freeipa_domain": "ipa.pilot.internal"},
			"audit1": {"ansible_host": "10.1.1.2"},
			"wazuh1": {"ansible_host": "10.1.1.3"}
		}}
	}`

	cases := []struct {
		name           string
		json           string
		targetGroup    string
		consumerGroups []string
		wantFQDN       string
		wantOK         bool
	}{
		{
			name:           "eligible: target enrolled, sole consumer group fully dns-covered",
			json:           baseJSON,
			targetGroup:    "log-server",
			consumerGroups: []string{"audit-log-forwarding"},
			wantFQDN:       "log1.ipa.pilot.internal",
			wantOK:         true,
		},
		{
			name: "target not a freeipa-client -> stays ineligible",
			json: `{
				"log-server": {"hosts": ["log1"]},
				"audit-log-forwarding": {"hosts": ["audit1"]},
				"freeipa-client": {"hosts": ["audit1"]},
				"freeipa-dns-client": {"hosts": ["log1", "audit1"]},
				"_meta": {"hostvars": {"log1": {"ansible_host": "10.1.1.1", "freeipa_domain": "ipa.pilot.internal"}}}
			}`,
			targetGroup:    "log-server",
			consumerGroups: []string{"audit-log-forwarding"},
			wantOK:         false,
		},
		{
			name: "consumer group has a host missing freeipa-dns-client -> ineligible",
			json: `{
				"log-server": {"hosts": ["log1"]},
				"audit-log-forwarding": {"hosts": ["audit1"]},
				"freeipa-client": {"hosts": ["log1", "audit1"]},
				"freeipa-dns-client": {"hosts": ["log1"]},
				"_meta": {"hostvars": {"log1": {"ansible_host": "10.1.1.1", "freeipa_domain": "ipa.pilot.internal"}}}
			}`,
			targetGroup:    "log-server",
			consumerGroups: []string{"audit-log-forwarding"},
			wantOK:         false,
		},
		{
			name:           "one of several consumer groups fails coverage -> whole upgrade declines",
			json:           baseJSON,
			targetGroup:    "log-server",
			consumerGroups: []string{"audit-log-forwarding", "keycloak"}, // "keycloak" group absent -> empty membership -> fails
			wantOK:         false,
		},
		{
			name:           "no known consumer group -> conservative decline",
			json:           baseJSON,
			targetGroup:    "log-server",
			consumerGroups: nil,
			wantOK:         false,
		},
		{
			name: "target has no freeipa_domain hostvar -> ineligible",
			json: `{
				"log-server": {"hosts": ["log1"]},
				"audit-log-forwarding": {"hosts": ["audit1"]},
				"freeipa-client": {"hosts": ["log1", "audit1"]},
				"freeipa-dns-client": {"hosts": ["log1", "audit1"]},
				"_meta": {"hostvars": {"log1": {"ansible_host": "10.1.1.1"}}}
			}`,
			targetGroup:    "log-server",
			consumerGroups: []string{"audit-log-forwarding"},
			wantOK:         false,
		},
		{
			name:           "target group absent -> ineligible, mirrors parseGroupHostFromInventoryList",
			json:           baseJSON,
			targetGroup:    "does-not-exist",
			consumerGroups: []string{"audit-log-forwarding"},
			wantOK:         false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fqdn, ok := fqdnForGroupHost(c.json, c.targetGroup, c.consumerGroups)
			if fqdn != c.wantFQDN || ok != c.wantOK {
				t.Errorf("fqdnForGroupHost() = (%q, %v), want (%q, %v)", fqdn, ok, c.wantFQDN, c.wantOK)
			}
		})
	}
}

// TestAutoHostVarConsumerGroups fixes which DefaultGroups a site-wide
// deploy must treat as "consumers" of a given cross-role var — a var can
// be auto-detected by more than one deployCatalog component (e.g.
// siem_forward_host by both audit-log-forwarding and wazuh-manager), and
// the FQDN-upgrade decision for a site-wide deploy must hold for every one
// of them, not just the first found.
func TestAutoHostVarConsumerGroups(t *testing.T) {
	if got := autoHostVarConsumerGroups("siem_forward_host"); !slices.Equal(got, []string{"audit-log-forwarding", "wazuh-manager"}) {
		t.Errorf("autoHostVarConsumerGroups(siem_forward_host) = %v, want [audit-log-forwarding wazuh-manager]", got)
	}
	if got := autoHostVarConsumerGroups("thanos_s3_target_host"); !slices.Equal(got, []string{"prometheus", "thanos-query"}) {
		t.Errorf("autoHostVarConsumerGroups(thanos_s3_target_host) = %v, want [prometheus thanos-query]", got)
	}
	if got := autoHostVarConsumerGroups("wazuh_manager_host"); !slices.Equal(got, []string{"wazuh-fim"}) {
		t.Errorf("autoHostVarConsumerGroups(wazuh_manager_host) = %v, want [wazuh-fim]", got)
	}
	if got := autoHostVarConsumerGroups("no-such-var"); len(got) != 0 {
		t.Errorf("autoHostVarConsumerGroups(no-such-var) = %v, want empty", got)
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

func TestResolveRosterAutoFillValue(t *testing.T) {
	defaultPath := "/ws/.vault/ipa-identity.yaml"

	t.Run("reuses value already set on another host", func(t *testing.T) {
		hostVars := map[string]map[string]any{
			"ipa-1":      {"freeipa_roster_file": "/ws/.vault/ipa-identity.yaml"},
			"nfs-client": {},
		}
		got := resolveRosterAutoFillValue([]string{"nfs-client"}, hostVars, defaultPath, true)
		if got != "/ws/.vault/ipa-identity.yaml" {
			t.Fatalf("got %q, want reused value", got)
		}
	})

	t.Run("falls back to default path when nothing else has it", func(t *testing.T) {
		hostVars := map[string]map[string]any{
			"nfs-client": {},
		}
		got := resolveRosterAutoFillValue([]string{"nfs-client"}, hostVars, defaultPath, true)
		if got != defaultPath {
			t.Fatalf("got %q, want default path %q", got, defaultPath)
		}
	})

	t.Run("gives up when default path doesn't exist and nothing else has it", func(t *testing.T) {
		hostVars := map[string]map[string]any{
			"nfs-client": {},
		}
		got := resolveRosterAutoFillValue([]string{"nfs-client"}, hostVars, defaultPath, false)
		if got != "" {
			t.Fatalf("got %q, want empty (no safe guess)", got)
		}
	})

	t.Run("backs off entirely when a roster host has an explicit value that disagrees with the candidate", func(t *testing.T) {
		hostVars := map[string]map[string]any{
			"nfs-client-1": {"freeipa_roster_file": "/ws/.vault/custom.yaml"},
			"nfs-client-2": {},
			"ipa-1":        {"freeipa_roster_file": "/ws/.vault/ipa-identity.yaml"},
		}
		got := resolveRosterAutoFillValue([]string{"nfs-client-1", "nfs-client-2"}, hostVars, defaultPath, true)
		if got != "" {
			t.Fatalf("got %q, want empty — must not override nfs-client-1's explicit value", got)
		}
	})

	// Regression: a freeipa-nfs-client deploy always pulls in its required
	// freeipa-nfs-server dependency, and that server's contract ALSO
	// requires freeipa_roster_file — so rosterHosts is pooled across both
	// components' hosts (see resolveRosterAutoFillValue's doc comment).
	// nfs-server already carrying its own explicit value is the normal
	// steady state, not a conflict, since it agrees with the candidate
	// pulled from the same inventory. Backing off here (the pre-fix
	// behavior) made the whole feature inert for the exact "server already
	// configured, clients still missing it" case it was built to solve.
	t.Run("fills client hosts even when an already-satisfied server host shares the candidate value", func(t *testing.T) {
		hostVars := map[string]map[string]any{
			"ipa-1":        {"freeipa_roster_file": "/ws/.vault/ipa-identity.yaml"},
			"nfs-server-1": {"freeipa_roster_file": "/ws/.vault/ipa-identity.yaml"},
			"nfs-client-1": {},
			"nfs-client-2": {},
		}
		got := resolveRosterAutoFillValue([]string{"nfs-client-1", "nfs-client-2", "nfs-server-1"}, hostVars, defaultPath, true)
		if got != "/ws/.vault/ipa-identity.yaml" {
			t.Fatalf("got %q, want the value nfs-server-1 and ipa-1 already agree on", got)
		}
	})
}

func TestAutoFillFreeIPARosterFile_SkipsWhenExplicitExtraVarAlreadySet(t *testing.T) {
	selected := []contract.Contract{{
		ID: "freeipa-nfs-client", Role: "freeipa-nfs-client",
		GroupVars: []contract.GroupVar{{Name: "freeipa_roster_file", Required: true}},
	}}
	scope := delivery.Scope{HostsByRole: map[string][]string{"freeipa-nfs-client": {"nfs-1"}}}
	extraVars := []string{"freeipa_roster_file=/already/set.yaml"}

	got, err := autoFillFreeIPARosterFile(context.Background(), io.Discard, selected, scope, "unused.yml", extraVars, vaultInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "freeipa_roster_file=/already/set.yaml" {
		t.Fatalf("got %v, want extraVars left untouched", got)
	}
}

func TestAutoFillFreeIPARosterFile_NoOpWhenNoComponentRequiresRoster(t *testing.T) {
	selected := []contract.Contract{{ID: "freeipa-client", Role: "freeipa-client"}}
	scope := delivery.Scope{HostsByRole: map[string][]string{"freeipa-client": {"client-1"}}}

	got, err := autoFillFreeIPARosterFile(context.Background(), io.Discard, selected, scope, "unused.yml", nil, vaultInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want no extra vars appended", got)
	}
}

func TestResolveWorkspaceManifestAutoFillValue(t *testing.T) {
	defaultPath := "/ws/freeipa-dns.yaml"

	t.Run("falls back to conventional path when it exists and nothing already has a value", func(t *testing.T) {
		hostVars := map[string]map[string]any{"freeipa-server": {}}
		got := resolveWorkspaceManifestAutoFillValue([]string{"freeipa-server"}, hostVars, "freeipa_dns_manifest_file", defaultPath, true)
		if got != defaultPath {
			t.Fatalf("got %q, want default path %q", got, defaultPath)
		}
	})

	t.Run("gives up when conventional path doesn't exist and nothing already has a value", func(t *testing.T) {
		hostVars := map[string]map[string]any{"freeipa-server": {}}
		got := resolveWorkspaceManifestAutoFillValue([]string{"freeipa-server"}, hostVars, "freeipa_dns_manifest_file", defaultPath, false)
		if got != "" {
			t.Fatalf("got %q, want empty (no safe guess)", got)
		}
	})

	t.Run("backs off entirely when a needing host already has an explicit value", func(t *testing.T) {
		hostVars := map[string]map[string]any{
			"freeipa-server": {"freeipa_dns_manifest_file": "/ws/.vault/custom-dns.yaml"},
		}
		got := resolveWorkspaceManifestAutoFillValue([]string{"freeipa-server"}, hostVars, "freeipa_dns_manifest_file", defaultPath, true)
		if got != "" {
			t.Fatalf("got %q, want empty — must not override freeipa-server's explicit value", got)
		}
	})
}

func TestAutoFillWorkspaceManifestFile_SkipsWhenExplicitExtraVarAlreadySet(t *testing.T) {
	selected := []contract.Contract{{
		ID: "freeipa-dns", Role: "freeipa-server",
		GroupVars: []contract.GroupVar{{Name: "freeipa_dns_manifest_file", Required: true}},
	}}
	scope := delivery.Scope{HostsByRole: map[string][]string{"freeipa-server": {"ipa-1"}}}
	extraVars := []string{"freeipa_dns_manifest_file=/already/set.yaml"}

	got, err := autoFillWorkspaceManifestFile(context.Background(), io.Discard, selected, scope, "unused.yml", extraVars, vaultInput{}, "freeipa_dns_manifest_file", "freeipa-dns.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "freeipa_dns_manifest_file=/already/set.yaml" {
		t.Fatalf("got %v, want extraVars left untouched", got)
	}
}

// TestAutoFillWorkspaceManifestFile_EndToEndAgainstRealInventory exercises
// the full function (not just resolveWorkspaceManifestAutoFillValue),
// including the real `ansible-inventory` shell-out, against a genuine
// temp-dir inventory + conventional manifest file — the same real-world
// case docs/runbooks/minimal-poc-configuration.md §3.2 documents (an
// operator asking whether freeipa_dns_manifest_file must always be typed
// by hand). Confirmed live 2026-08-19: `ansible-inventory` picks up the
// plain host var correctly and the function fills in the conventional path.
func TestAutoFillWorkspaceManifestFile_EndToEndAgainstRealInventory(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	manifest := filepath.Join(dir, "freeipa-dns.yaml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    freeipa-server:\n      ansible_host: 10.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("schema_version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	selected := []contract.Contract{{
		ID: "freeipa-dns", Role: "freeipa-server",
		GroupVars: []contract.GroupVar{{Name: "freeipa_dns_manifest_file", Required: true}},
	}}
	scope := delivery.Scope{HostsByRole: map[string][]string{"freeipa-server": {"freeipa-server"}}}

	got, err := autoFillWorkspaceManifestFile(context.Background(), io.Discard, selected, scope, inv, nil, vaultInput{}, "freeipa_dns_manifest_file", "freeipa-dns.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "freeipa_dns_manifest_file=" + manifest
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want [%q]", got, want)
	}
}

func TestAutoFillWorkspaceManifestFile_NoOpWhenNoComponentRequiresIt(t *testing.T) {
	selected := []contract.Contract{{ID: "freeipa-server", Role: "freeipa-server"}}
	scope := delivery.Scope{HostsByRole: map[string][]string{"freeipa-server": {"ipa-1"}}}

	got, err := autoFillWorkspaceManifestFile(context.Background(), io.Discard, selected, scope, "unused.yml", nil, vaultInput{}, "freeipa_dns_manifest_file", "freeipa-dns.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want no extra vars appended", got)
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

// TestResolveDeploymentScope_LimitDoesNotAbortZeroHostSiteComponent
// reproduces a live bug reported against inventories/infra-config/inventory.yml:
// a site-wide deploy with --limit failed with "resolve component \"dns\" role
// \"dns\": ansible dns --list-hosts: exit status 1: ... leaves us with no
// hosts to target" even though the same deploy without --limit succeeds by
// silently skipping the (legitimately unused) dns role via allowEmpty.
//
// Root cause: ansible's own CLI reports "pattern matches zero hosts"
// differently depending on --limit — a [WARNING] + exit 0 without --limit,
// a hard [ERROR] + exit 1 with --limit — and resolvePatternHosts propagated
// that exit-1 as a hard error before allowEmpty ever got a chance to skip it.
func TestResolveDeploymentScope_LimitDoesNotAbortZeroHostSiteComponent(t *testing.T) {
	root := repoRootForTest(t)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	invJSON := `{"_meta": {"hostvars": {"host-a": {}}}, "dns": {"hosts": []}, "docker": {"hosts": ["host-a"]}}`
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '"+invJSON+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Mimics real `ansible <pattern> --list-hosts [--limit <limit>]`: the
	// "dns" role has zero hosts in this fixture, exactly like the empty
	// `dns: {hosts: {}}` group in the reported inventory.
	ansibleFixture := `#!/bin/sh
pattern="$1"
case "$pattern" in
  docker)
    printf '%s\n' '  hosts (1):' '    host-a'
    exit 0
    ;;
  dns)
    case "$*" in
      *--limit*)
        echo '[ERROR]: Specified inventory, host pattern and/or --limit leaves us with no hosts to target.' >&2
        exit 1
        ;;
      *)
        echo '[WARNING]: No hosts matched, nothing to do' >&2
        printf '%s\n' '  hosts (0):'
        exit 0
        ;;
    esac
    ;;
  *)
    echo "unexpected pattern: $pattern" >&2
    exit 2
    ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(ansibleFixture), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	applied, _, _, hosts, err := resolveDeploymentScope(context.Background(), catalog, []string{"dns", "docker"}, "fake-inventory.yml", "host-a", nil, true)
	if err != nil {
		t.Fatalf("site-wide deploy with --limit must skip the zero-host dns role, not abort: %v", err)
	}
	if len(applied) != 1 || applied[0].ID != "docker" {
		t.Fatalf("applied = %v, want only docker (dns has zero hosts and must be skipped)", applied)
	}
	if !slices.Equal(hosts, []string{"host-a"}) {
		t.Fatalf("hosts = %v, want [host-a]", hosts)
	}
}
