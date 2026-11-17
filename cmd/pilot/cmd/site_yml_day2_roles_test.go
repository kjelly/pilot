package cmd

// Issue #362: freeipa-server-replica and freeipa-dns-client are host-assigned
// roles that playbooks/site.yml did not import. optInRolesAssignedInScope and
// componentsForPlaybook correctly refuse to list a component Ansible has no
// play for (9550b38a), so a site-wide `pilot deploy` dropped both silently for
// every host the inventory assigned them to, and still exited 0. These tests
// run the real contracts/ catalog and the real playbooks/site.yml through
// deploy.go's selection code, with a fake ansible-inventory/ansible that
// answers from a group table, and (when ansible-playbook is installed) ask
// the real ansible-playbook which tasks those tags select.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// installFakeInventoryTools puts an ansible-inventory and an ansible on PATH
// that answer from groups (group name -> hosts), for the calls deploy.go
// makes: `ansible-inventory -i <inv> --list` and `ansible <pattern> -i <inv>
// --list-hosts [--limit a,b]`. A pattern that matches nothing gives
// ansible's real outputs: "hosts (0):" without --limit, a hard error with it
// (resolvePatternHosts normalizes that to zero hosts).
func installFakeInventoryTools(t *testing.T, groups map[string][]string) {
	t.Helper()
	binDir := t.TempDir()

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	var table strings.Builder
	hostSet := map[string]bool{}
	for _, name := range names {
		table.WriteString(name + " " + strings.Join(groups[name], " ") + "\n")
		for _, host := range groups[name] {
			hostSet[host] = true
		}
	}
	tablePath := filepath.Join(binDir, "groups.txt")
	if err := os.WriteFile(tablePath, []byte(table.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	hostvars := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hostvars = append(hostvars, fmt.Sprintf("%q:{}", host))
	}
	sort.Strings(hostvars)
	groupJSON := make([]string, 0, len(names))
	for _, name := range names {
		hosts := make([]string, 0, len(groups[name]))
		for _, host := range groups[name] {
			hosts = append(hosts, fmt.Sprintf("%q", host))
		}
		groupJSON = append(groupJSON, fmt.Sprintf("%q:{\"hosts\":[%s]}", name, strings.Join(hosts, ",")))
	}
	invJSON := `{"_meta":{"hostvars":{` + strings.Join(hostvars, ",") + `}},` + strings.Join(groupJSON, ",") + `}`
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '"+invJSON+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	ansible := `#!/bin/sh
groups_file='` + tablePath + `'
pattern=$1
limit=
prev=
for arg in "$@"; do
  if [ "$prev" = --limit ]; then limit=$arg; fi
  prev=$arg
done
if [ "$pattern" = all ]; then
  hosts=$(awk '{ for (i = 2; i <= NF; i++) print $i }' "$groups_file" | sort -u)
else
  hosts=$(awk -v g="$pattern" '$1 == g { for (i = 2; i <= NF; i++) print $i }' "$groups_file")
fi
selected=
for h in $hosts; do
  keep=1
  if [ -n "$limit" ] && [ "$limit" != all ]; then
    keep=0
    old_ifs=$IFS
    IFS=,
    for l in $limit; do
      if [ "$l" = "$h" ]; then keep=1; fi
    done
    IFS=$old_ifs
  fi
  if [ "$keep" = 1 ]; then selected="$selected $h"; fi
done
set -- $selected
if [ $# -eq 0 ] && [ -n "$limit" ]; then
  echo "ERROR! Specified inventory, host pattern and/or --limit parameters yield an empty list of hosts: leaves us with no hosts to target." >&2
  exit 1
fi
printf '  hosts (%d):\n' $#
for h in "$@"; do printf '    %s\n' "$h"; done
`
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(ansible), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// day2RolesInventory is the topology of issue #362: a primary, a replica
// host and a client that is also a freeipa-dns-client, with the client's
// other roles as in a normal site (login-probe needs freeipa-client and
// host-monitoring on the same host).
func day2RolesInventory() map[string][]string {
	return map[string][]string{
		"freeipa-server":         {"ipa1"},
		"freeipa-server-replica": {"ipa2"},
		"freeipa-client":         {"c1"},
		"login-probe":            {"c1"},
		"host-monitoring":        {"c1"},
		"freeipa-dns-client":     {"c1"},
	}
}

// siteWideIncludedComponentIDs is what a site-wide deploy selects with no
// host-assigned opt-in role at all: every Site.Include component whose apply
// playbook site.yml imports. It is derived from the catalog, not from the
// code under test.
func siteWideIncludedComponentIDs(t *testing.T, catalog contract.Catalog) []string {
	t.Helper()
	imported, err := siteYMLImportedPlaybooks()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, component := range catalog.Components() {
		if component.Site.Include && imported[component.Playbooks.Apply] {
			ids = append(ids, component.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

var day2Roles = []string{"freeipa-server-replica", "freeipa-dns-client"}

// AC1, assigned: the inventory gives a host each of the two roles, and a
// site-wide deploy must select both components. On the base commit neither
// apply playbook is in site.yml, so componentsForPlaybook drops both.
func TestSiteYMLDay2RolesSelectedWhenAssigned(t *testing.T) {
	_, catalog := loadRealCatalogForSiteTests(t)
	installFakeInventoryTools(t, day2RolesInventory())

	components, err := componentsForPlaybook(context.Background(), catalog, "playbooks/site.yml", "inventory.yml", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range day2Roles {
		if !slices.Contains(components, id) {
			t.Errorf("site-wide deploy dropped %s although the inventory assigns it to a host: %v", id, components)
		}
	}
	// Selection is additive: the always-on components are still there.
	for _, id := range siteWideIncludedComponentIDs(t, catalog) {
		if !slices.Contains(components, id) {
			t.Errorf("site-wide deploy lost always-on component %s: %v", id, components)
		}
	}
}

// AC1, unassigned: no host has either role. The selection must be exactly
// what it was before the two imports, with and without --tags, even though
// the contracts now carry site.tags: a non-empty site.tags only narrows a
// component the role assignment already selected (componentMatchesTags); it
// never selects one.
func TestSiteYMLDay2RolesSelectionUnchangedWhenUnassigned(t *testing.T) {
	_, catalog := loadRealCatalogForSiteTests(t)
	installFakeInventoryTools(t, map[string][]string{
		"freeipa-server": {"ipa1"},
		"freeipa-client": {"c1"},
	})
	want := siteWideIncludedComponentIDs(t, catalog)
	for _, id := range day2Roles {
		if slices.Contains(want, id) {
			t.Fatalf("%s must stay site.include=false: it is selected by host assignment only", id)
		}
	}

	t.Run("no tags", func(t *testing.T) {
		got, err := componentsForPlaybook(context.Background(), catalog, "playbooks/site.yml", "inventory.yml", "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("selection changed with no host assigned either role:\n got  %v\n want %v", got, want)
		}
	})

	for _, tags := range []string{"freeipa", "freeipa-server-replica,freeipa-dns-client", "freeipa-dns-client"} {
		t.Run("tags "+tags, func(t *testing.T) {
			got, err := componentsForPlaybook(context.Background(), catalog, "playbooks/site.yml", "inventory.yml", "", tags, nil)
			if err != nil {
				// An explicit tag that names only a component without a
				// host selects nothing; that is today's behavior too.
				return
			}
			for _, id := range day2Roles {
				if slices.Contains(got, id) {
					t.Errorf("--tags %s selected %s with no host assigned its role: %v", tags, id, got)
				}
			}
		})
	}
}

// With a host assigned, site.tags makes `--tags freeipa` (one of the
// documented ways to run a class of components) record and verify both
// components, as it does for freeipa-server and freeipa-client; an unrelated
// tag still leaves them out.
func TestSiteYMLDay2RolesFollowTheirTags(t *testing.T) {
	_, catalog := loadRealCatalogForSiteTests(t)
	installFakeInventoryTools(t, day2RolesInventory())

	got, err := componentsForPlaybook(context.Background(), catalog, "playbooks/site.yml", "inventory.yml", "", "freeipa", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range append([]string{"freeipa-server", "freeipa-client"}, day2Roles...) {
		if !slices.Contains(got, id) {
			t.Errorf("--tags freeipa did not select %s: %v", id, got)
		}
	}

	got, err = componentsForPlaybook(context.Background(), catalog, "playbooks/site.yml", "inventory.yml", "", "observability", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range day2Roles {
		if slices.Contains(got, id) {
			t.Errorf("--tags observability selected %s: %v", id, got)
		}
	}
}

// day2Scenario runs the three steps of executeRecordedDeployment that decide
// what Ansible is told for a site-wide, --limit-ed run: the component
// selection, the dependency-expanded scope, and the effective limit and
// apply tags (every host is available).
type day2Scenario struct {
	applied, selected []string
	hosts             []string
	expanded          bool
	limit             string
	applyTags         string
	verifyTags        string
}

func runDay2Scenario(t *testing.T, catalog contract.Catalog, limit string) day2Scenario {
	t.Helper()
	ctx := context.Background()
	components, err := componentsForPlaybook(ctx, catalog, "playbooks/site.yml", "inventory.yml", limit, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	applied, selected, _, hosts, expanded, err := resolveDeploymentScope(ctx, catalog, components, "inventory.yml", limit, nil, true)
	if err != nil {
		t.Fatalf("resolveDeploymentScope: %v", err)
	}
	tagScopes := effectiveDeploymentTagScopes("playbooks/site.yml", "", applied, selected, expanded)
	return day2Scenario{
		applied:    contractIDs(applied),
		selected:   contractIDs(selected),
		hosts:      hosts,
		expanded:   expanded,
		limit:      effectiveDeploymentLimit("playbooks/site.yml", limit, hosts, hosts, expanded),
		applyTags:  tagScopes.Apply,
		verifyTags: tagScopes.Verification,
	}
}

// AC1, partial --limit. The client c1 sits in freeipa-client, login-probe,
// host-monitoring and freeipa-dns-client. Its required providers are on
// other hosts: freeipa-client -> freeipa-server (two hops from login-probe)
// and freeipa-dns-client -> freeipa-server. The replica is only a planOnly
// dependency of freeipa-dns-client, so it is not pulled in.
func TestSiteYMLDay2RolesPartialLimitOnTheClient(t *testing.T) {
	_, catalog := loadRealCatalogForSiteTests(t)
	installFakeInventoryTools(t, day2RolesInventory())

	got := runDay2Scenario(t, catalog, "c1")
	if want := []string{"freeipa-client", "freeipa-dns-client", "host-monitoring", "login-probe"}; !slices.Equal(got.applied, want) {
		t.Errorf("applied = %v, want %v", got.applied, want)
	}
	if want := []string{"freeipa-client", "freeipa-dns-client", "freeipa-server", "host-monitoring", "login-probe"}; !slices.Equal(got.selected, want) {
		t.Errorf("selected = %v, want %v (the primary comes in by dependency, the replica does not)", got.selected, want)
	}
	if !slices.Equal(got.hosts, []string{"c1", "ipa1"}) {
		t.Errorf("hosts = %v, want [c1 ipa1]", got.hosts)
	}
	if !got.expanded {
		t.Error("dependencyExpandedLimit = false, want true: the primary is outside --limit")
	}
	if got.limit != "localhost,c1,ipa1" {
		t.Errorf("effective limit = %q, want localhost,c1,ipa1", got.limit)
	}
	if want := "freeipa-client,freeipa-dns-client,freeipa-server,host-monitoring,login-probe"; got.applyTags != want {
		t.Errorf("apply tags = %q, want %q", got.applyTags, want)
	}
	if got.verifyTags != "" {
		t.Errorf("verification tags = %q, want empty: dependency expansion must not narrow verification", got.verifyTags)
	}
	for _, tag := range strings.Split(got.applyTags, ",") {
		if tag == "freeipa-server-replica" {
			t.Errorf("apply tags %q select the replica, which --limit c1 does not cover", got.applyTags)
		}
	}
}

// AC1, partial --limit on the replica host: the replica is selected by its
// host assignment, the primary comes in as its required provider, and the
// dns-client (only on c1) stays out.
func TestSiteYMLDay2RolesPartialLimitOnTheReplica(t *testing.T) {
	_, catalog := loadRealCatalogForSiteTests(t)
	installFakeInventoryTools(t, day2RolesInventory())

	got := runDay2Scenario(t, catalog, "ipa2")
	if want := []string{"freeipa-server-replica"}; !slices.Equal(got.applied, want) {
		t.Errorf("applied = %v, want %v", got.applied, want)
	}
	if want := []string{"freeipa-server", "freeipa-server-replica"}; !slices.Equal(got.selected, want) {
		t.Errorf("selected = %v, want %v", got.selected, want)
	}
	if !got.expanded || got.limit != "localhost,ipa1,ipa2" {
		t.Errorf("expanded=%v limit=%q, want true and localhost,ipa1,ipa2", got.expanded, got.limit)
	}
	if want := "freeipa-server,freeipa-server-replica"; got.applyTags != want {
		t.Errorf("apply tags = %q, want %q", got.applyTags, want)
	}
	if got.verifyTags != "" {
		t.Errorf("verification tags = %q, want empty", got.verifyTags)
	}
}

// requireAnsiblePlaybookForSiteTests skips without ansible-playbook, or when
// it cannot even parse the real site.yml here (the collections the plays use
// are missing). PILOT_REQUIRE_CONTAINER_TESTS=1 (make site-day2-roles-test,
// CI's Playbook integration job) turns either into a failure.
func requireAnsiblePlaybookForSiteTests(t *testing.T, root string) {
	t.Helper()
	required := os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1"
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if required {
			t.Fatalf("ansible-playbook not installed: %v (PILOT_REQUIRE_CONTAINER_TESTS=1)", err)
		}
		t.Skipf("ansible-playbook not installed: %v; the tag-selection oracle below did not run", err)
	}
	out, err := exec.Command("ansible-playbook", "--syntax-check", "-i", "localhost,", filepath.Join(root, "playbooks", "site.yml")).CombinedOutput()
	if err != nil {
		if required {
			t.Fatalf("ansible-playbook cannot parse playbooks/site.yml: %v\n%s", err, out)
		}
		t.Skipf("ansible-playbook cannot parse playbooks/site.yml here (collections missing?): %v\n%s", err, out)
	}
}

// listSiteTasks runs the real `ansible-playbook --list-tasks` over the real
// playbooks/site.yml with the tags and limit pilot would pass, against a real
// inventory file, and returns its output. This is the oracle that does not
// share deploy.go's reading of site.yml: it is Ansible deciding which tasks
// the tags select.
func listSiteTasks(t *testing.T, root string, groups map[string][]string, tags, limit string) string {
	t.Helper()
	dir := t.TempDir()
	var inv strings.Builder
	inv.WriteString("all:\n  children:\n")
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		inv.WriteString("    " + name + ":\n      hosts:\n")
		for _, host := range groups[name] {
			inv.WriteString("        " + host + ":\n          ansible_connection: local\n")
		}
	}
	invPath := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(invPath, []byte(inv.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ansible.cfg")
	if err := os.WriteFile(cfg, []byte("[defaults]\nhost_key_checking = False\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--list-tasks", "-i", invPath, "--limit", limit, filepath.Join(root, "playbooks", "site.yml")}
	if tags != "" {
		args = append(args, "--tags", tags)
	}
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+cfg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

const (
	replicaInstallTask   = "FreeIPA replica — step 2/2: ipa-replica-install (promote; first run 8-12 min)"
	dnsClientResolveTask = "Apply the FreeIPA DNS resolver baseline to this host"
)

// The tags a limited site deploy hands to Ansible must select the tasks of
// the roles the run is about, according to Ansible itself, and must not
// select the other role's tasks. With the imports missing (the base), neither
// role has a task to list.
func TestSiteYMLDay2RolesTagsSelectTheirTasksInAnsible(t *testing.T) {
	root, catalog := loadRealCatalogForSiteTests(t)
	requireAnsiblePlaybookForSiteTests(t, root)
	groups := day2RolesInventory()
	installFakeInventoryTools(t, groups)

	onClient := runDay2Scenario(t, catalog, "c1")
	listed := listSiteTasks(t, root, groups, onClient.applyTags, onClient.limit)
	if !strings.Contains(listed, dnsClientResolveTask) {
		t.Errorf("--tags %s --limit %s: ansible lists no freeipa-dns-client task (%q); output:\n%s", onClient.applyTags, onClient.limit, dnsClientResolveTask, listed)
	}
	if strings.Contains(listed, replicaInstallTask) {
		t.Errorf("--tags %s selects the replica install although --limit c1 does not cover the replica; output:\n%s", onClient.applyTags, listed)
	}

	onReplica := runDay2Scenario(t, catalog, "ipa2")
	listed = listSiteTasks(t, root, groups, onReplica.applyTags, onReplica.limit)
	if !strings.Contains(listed, replicaInstallTask) {
		t.Errorf("--tags %s --limit %s: ansible lists no replica task (%q); output:\n%s", onReplica.applyTags, onReplica.limit, replicaInstallTask, listed)
	}
	if strings.Contains(listed, dnsClientResolveTask) {
		t.Errorf("--tags %s selects the dns-client tasks although --limit ipa2 does not cover it; output:\n%s", onReplica.applyTags, listed)
	}

	// The full site-wide run (no --tags) reaches both.
	listed = listSiteTasks(t, root, groups, "", "all")
	for _, task := range []string{replicaInstallTask, dnsClientResolveTask} {
		if !strings.Contains(listed, task) {
			t.Errorf("a full site.yml run does not list %q", task)
		}
	}
}
