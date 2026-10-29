package inventory

import (
	"errors"

	"go.yaml.in/yaml/v3"
)

// errCyclicYAML is a YAML document whose aliases or merge keys lead back to
// the node they started from. The message never holds document content: the
// document may be a vault or a roster, and holds passwords.
var errCyclicYAML = errors.New("YAML aliases or merge keys refer to themselves")

// parseYAMLDocument parses data into a node tree and refuses one whose alias
// graph has a cycle. Unmarshalling into a yaml.Node never expands an alias, so
// yaml.v3's own "anchor contains itself" and "excessive aliasing" checks,
// which run while decoding into a Go value, never run: a self-referencing
// merge key reaches here whole, and a walk that follows aliases and merge
// keys — mappingValue — would recurse until the stack overflowed (fatal, not
// recoverable) or, on an acyclic but heavily shared graph, take exponential
// time. Every document pilot reads as a node tree goes through this function,
// so no traversal sees an unchecked graph (AGENTS.md §5.11).
func parseYAMLDocument(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if err := checkAliasGraph(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

const (
	aliasUnseen = iota
	aliasOnPath // grey: on the current DFS path
	aliasDone   // black: every node reachable from it is known to be acyclic
)

// checkAliasGraph reports errCyclicYAML when following children and aliases
// from root leads back to a node on the path. It is a depth-first search that
// visits each node once, so its cost is linear in the document however many
// times an anchor is shared: a diamond — one anchor used twice, as by
// "<<: [*a, *a]" — is valid and accepted; only a true cycle is refused.
func checkAliasGraph(root *yaml.Node) error {
	state := map[*yaml.Node]uint8{}
	var visit func(*yaml.Node) error
	visit = func(n *yaml.Node) error {
		if n == nil {
			return nil
		}
		switch state[n] {
		case aliasDone:
			return nil
		case aliasOnPath:
			return errCyclicYAML
		}
		state[n] = aliasOnPath
		for _, child := range n.Content {
			if err := visit(child); err != nil {
				return err
			}
		}
		if n.Kind == yaml.AliasNode {
			if err := visit(n.Alias); err != nil {
				return err
			}
		}
		state[n] = aliasDone
		return nil
	}
	return visit(root)
}
