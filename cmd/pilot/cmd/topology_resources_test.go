package cmd

import (
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/vmtarget"
)

// guestVisibleRAMPercent is how much of a vm-target node's configured memory
// `free -m` reports inside the guest, which is what pilot deploy's resource
// check compares with a contract's minRAMMiB (hostFactsProbeCommand). An
// AlmaLinux 9 node with `memory: 4096` reported 3911 MiB on 2026-10-01.
const guestVisibleRAMPercent = 95

// guestVisibleDiskPercent is the same for the disk: deploy compares the
// space available on / (`df -BG --output=avail /`), which a 30 GiB AlmaLinux
// 9 node reported as 28 GiB on 2026-10-01.
const guestVisibleDiskPercent = 90

// TestTopologyNodesMeetContractResourceMinimums keeps every committed
// topology deployable with pilot deploy: each node must meet the resource
// minimums of the contracts for every group it is in. A real site-wide
// deploy on docs/topologies/dns-tier-topology.yaml stopped before any
// playbook ran because its FreeIPA node had `memory: 4096`, which the guest
// sees as 3911 MiB against freeipa-server's minRAMMiB of 4096 (2026-10-01).
// `vm-target topology test` does not run that check, so only pilot deploy
// found it.
func TestTopologyNodesMeetContractResourceMinimums(t *testing.T) {
	root := repoRootForTest(t)
	t.Setenv("PILOT_ROOT", root)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "docs", "topologies", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no topology files found under docs/topologies")
	}
	checked := 0
	for _, path := range paths {
		spec, err := vmtarget.LoadTopologySpec(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		for _, node := range spec.Nodes {
			// A field left out gets vm-target's default.
			if node.VCPUs == 0 {
				node.VCPUs = vmtarget.DefaultVCPUs
			}
			if node.MemoryMB == 0 {
				node.MemoryMB = vmtarget.DefaultMemoryMB
			}
			if node.DiskGB == 0 {
				node.DiskGB = vmtarget.DefaultDiskGB
			}
			for _, group := range node.Groups {
				for _, component := range catalog.ComponentsForRole(group) {
					checked++
					min := component.Resources
					where := filepath.Base(path) + " node " + node.Name + " (group " + group + ", contract " + component.ID + ")"
					if node.VCPUs < min.MinCPU {
						t.Errorf("%s: vcpus %d < minCPU %d", where, node.VCPUs, min.MinCPU)
					}
					if ram := node.MemoryMB * guestVisibleRAMPercent / 100; ram < min.MinRAMMiB {
						t.Errorf("%s: memory %d MiB is about %d MiB inside the guest, below minRAMMiB %d; use at least %d",
							where, node.MemoryMB, ram, min.MinRAMMiB, (min.MinRAMMiB*100+guestVisibleRAMPercent-1)/guestVisibleRAMPercent)
					}
					if disk := node.DiskGB * guestVisibleDiskPercent / 100; disk < min.MinDiskGiB {
						t.Errorf("%s: disk %d GiB leaves about %d GiB on /, below minDiskGiB %d", where, node.DiskGB, disk, min.MinDiskGiB)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no topology node group matched a contract role; the test checked nothing")
	}
}
