package vmtarget

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TopologyNode declares one VM in a multi-node topology spec: how to
// provision it (mirrors Options), which ansible groups it belongs to
// (for RenderGroupedInventory), and which peers must be pinned into its
// /etc/hosts (for `vm-target wire`).
type TopologyNode struct {
	Name          string   `yaml:"name"`
	BaseImage     string   `yaml:"base_image"`
	SSHUser       string   `yaml:"ssh_user"`
	VCPUs         int      `yaml:"vcpus"`
	MemoryMB      int      `yaml:"memory"`
	DiskGB        int      `yaml:"disk"`
	Network       string   `yaml:"network"`
	Hosts         []string `yaml:"hosts"`
	Groups        []string `yaml:"groups"`
	Wire          []string `yaml:"wire"`
	SSHTimeout    string   `yaml:"ssh_timeout"`  // e.g. "8m"; empty = Manager default (2m)
	BootTimeout   string   `yaml:"boot_timeout"` // e.g. "8m"; empty = Manager default (3m)
	KeepOnFailure bool     `yaml:"keep_on_failure"`
}

// TopologySpec is the top-level shape of a `vm-target topology` YAML
// file: a declarative description of every node in a multi-VM test
// scenario (e.g. FreeIPA primary+replica+client), so bring-up, ansible
// group inventory, and /etc/hosts wiring are all driven from one file
// instead of hand-assembled shell commands.
type TopologySpec struct {
	Nodes []TopologyNode `yaml:"nodes"`
}

// LoadTopologySpec reads and validates a topology YAML file.
func LoadTopologySpec(path string) (*TopologySpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read topology spec %s: %w", path, err)
	}
	var spec TopologySpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("parse topology spec %s: %w", path, err)
	}
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("topology spec %s: %w", path, err)
	}
	return &spec, nil
}

// Validate checks structural invariants that would otherwise surface as
// confusing failures partway through a multi-VM bring-up: unique
// non-empty names, and wire/group references that only point at nodes
// actually declared in the same spec.
func (s *TopologySpec) Validate() error {
	if len(s.Nodes) == 0 {
		return errors.New("at least one node is required")
	}
	names := make(map[string]bool, len(s.Nodes))
	for _, n := range s.Nodes {
		if n.Name == "" {
			return errors.New("every node needs a name")
		}
		if !validName(n.Name) {
			return fmt.Errorf("node %q: invalid name (want [a-zA-Z0-9_.-]+)", n.Name)
		}
		if names[n.Name] {
			return fmt.Errorf("duplicate node name %q", n.Name)
		}
		names[n.Name] = true
	}
	for _, n := range s.Nodes {
		for _, w := range n.Wire {
			peerName := w
			if i := strings.IndexByte(w, '='); i >= 0 {
				peerName = w[:i]
			}
			if peerName == "" {
				return fmt.Errorf("node %q: empty wire peer name", n.Name)
			}
			if peerName == n.Name {
				return fmt.Errorf("node %q: cannot wire itself", n.Name)
			}
			if !names[peerName] {
				return fmt.Errorf("node %q: wire peer %q is not a node in this spec", n.Name, peerName)
			}
		}
		if n.SSHTimeout != "" {
			if _, err := time.ParseDuration(n.SSHTimeout); err != nil {
				return fmt.Errorf("node %q: invalid ssh_timeout %q: %w", n.Name, n.SSHTimeout, err)
			}
		}
		if n.BootTimeout != "" {
			if _, err := time.ParseDuration(n.BootTimeout); err != nil {
				return fmt.Errorf("node %q: invalid boot_timeout %q: %w", n.Name, n.BootTimeout, err)
			}
		}
	}
	return nil
}

// Groups returns the group order (first-seen across nodes, stable) and
// group->member-name map implied by every node's `groups:` list, in the
// shape RenderGroupedInventory expects.
func (s *TopologySpec) Groups() (order []string, groups map[string][]string) {
	groups = make(map[string][]string)
	for _, n := range s.Nodes {
		for _, g := range n.Groups {
			if _, ok := groups[g]; !ok {
				order = append(order, g)
			}
			groups[g] = append(groups[g], n.Name)
		}
	}
	return order, groups
}

// Node looks up a node by name.
func (s *TopologySpec) Node(name string) (TopologyNode, bool) {
	for _, n := range s.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return TopologyNode{}, false
}

// ToOptions builds the vmtarget.Options for provisioning this node.
// Manager.Up already defaults SSHUser/VCPUs/MemoryMB/DiskGB/Network when
// zero, so only BaseImage needs a default here (Up has none — it treats
// an empty BaseImage as a hard error, same as the `vm-target up` CLI).
// SSHTimeout/BootTimeout are validated as parseable durations by
// Validate, so the only possible error here is a caller skipping
// Validate (e.g. constructing a TopologyNode by hand in a test).
func (n TopologyNode) ToOptions() (Options, error) {
	baseImage := n.BaseImage
	if baseImage == "" {
		baseImage = "ubuntu-24.04"
	}
	opt := Options{
		Name:          n.Name,
		BaseImage:     baseImage,
		SSHUser:       n.SSHUser,
		VCPUs:         n.VCPUs,
		MemoryMB:      n.MemoryMB,
		DiskGB:        n.DiskGB,
		Network:       n.Network,
		Hosts:         n.Hosts,
		KeepOnFailure: n.KeepOnFailure,
	}
	if n.SSHTimeout != "" {
		d, err := time.ParseDuration(n.SSHTimeout)
		if err != nil {
			return Options{}, fmt.Errorf("node %q: invalid ssh_timeout %q: %w", n.Name, n.SSHTimeout, err)
		}
		opt.SSHTimeout = d
	}
	if n.BootTimeout != "" {
		d, err := time.ParseDuration(n.BootTimeout)
		if err != nil {
			return Options{}, fmt.Errorf("node %q: invalid boot_timeout %q: %w", n.Name, n.BootTimeout, err)
		}
		opt.BootTimeout = d
	}
	return opt, nil
}
