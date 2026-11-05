package mcpremote

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/configpolicy"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/mcpwire"
	"go.yaml.in/yaml/v3"
)

// deniedPathPrefixes are container locations a configuration value must
// never name literally: the environment's secrets and data dir, and the
// observe session area. They are reached only through /pilot/config.
var deniedPathPrefixes = []string{mcpwire.ContainerVaultDir, mcpwire.ContainerDataDir, mcpwire.ContainerTmpDir}

// CheckPathScope parses every .yml/.yaml file of the snapshot and rejects
// any scalar that, once cleaned, is or lies under a denied prefix. The walk
// follows the node tree only, never an alias, so a cyclic or heavily shared
// alias graph costs one visit per node.
func CheckPathScope(root string, files []string) error {
	for _, rel := range files {
		if ext := path.Ext(rel); ext != ".yml" && ext != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return errorf(mcpwire.CodeRuntimeError, "read %s: %v", rel, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var doc yaml.Node
			err := dec.Decode(&doc)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errorf(mcpwire.CodeSnapshotInvalid, "%s is not valid YAML", rel)
			}
			if bad := firstDeniedScalar(&doc); bad != nil {
				return errorf(mcpwire.CodePathOutOfScope, "%s:%d: refers to %s; use a /pilot/config path", rel, bad.Line, deniedPrefixOf(bad.Value))
			}
		}
	}
	return nil
}

func firstDeniedScalar(root *yaml.Node) *yaml.Node {
	stack := []*yaml.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.Kind {
		case yaml.AliasNode:
			continue
		case yaml.ScalarNode:
			if deniedPrefixOf(n.Value) != "" {
				return n
			}
		}
		for i := len(n.Content) - 1; i >= 0; i-- {
			stack = append(stack, n.Content[i])
		}
	}
	return nil
}

func deniedPrefixOf(value string) string {
	if !strings.HasPrefix(value, "/") {
		return ""
	}
	clean := path.Clean(value)
	for _, p := range deniedPathPrefixes {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return p
		}
	}
	return ""
}

// CheckHostsEnv requires every host in root/hosts.yml to carry env (an
// empty env means sandbox), so one environment's configuration is never
// paired with another environment's .vault.
func CheckHostsEnv(root, env string) error {
	data, err := os.ReadFile(filepath.Join(root, "hosts.yml"))
	if err != nil {
		if os.IsNotExist(err) {
			return errorf(mcpwire.CodeSnapshotInvalid, "snapshot has no hosts.yml at its root")
		}
		return errorf(mcpwire.CodeRuntimeError, "read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return errorf(mcpwire.CodeSnapshotInvalid, "hosts.yml: %v", err)
	}
	for _, h := range hf.Hosts {
		hostEnv := h.Env
		if hostEnv == "" {
			hostEnv = "sandbox"
		}
		if hostEnv != env {
			return errorf(mcpwire.CodeEnvMismatch, "host %s has env %s, this session is %s", h.Name, hostEnv, env)
		}
	}
	return nil
}

// CheckSecretPolicy loads the contract catalog strictly from the image and
// runs pilot's group_vars/host_vars secret check on the snapshot.
func CheckSecretPolicy(pilotRoot, root string) error {
	loader, err := contract.NewLoader(pilotRoot)
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "load contracts: %v", err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "load contracts: %v", err)
	}
	violations, err := configpolicy.New(catalog).Workspace(root)
	if err != nil {
		return errorf(mcpwire.CodeSnapshotInvalid, "secret policy: %v", err)
	}
	if len(violations) == 0 {
		return nil
	}
	lines := make([]string, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.String())
	}
	sort.Strings(lines)
	if len(lines) > 3 {
		lines = append(lines[:3], fmt.Sprintf("and %d more", len(violations)-3))
	}
	return errorf(mcpwire.CodeSecretPolicyViolation, "%s", strings.Join(lines, "; "))
}
