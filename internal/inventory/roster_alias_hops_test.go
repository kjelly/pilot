package inventory

import (
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// aliasChain is links alias nodes, each naming the next, the last naming a
// scalar. yaml.v3 never builds this — its alias points straight at the node
// it names — so only a hand-built tree reaches resolveAlias's hop bound.
func aliasChain(links int) (head, target *yaml.Node) {
	target = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x"}
	head = target
	for i := 0; i < links; i++ {
		head = &yaml.Node{Kind: yaml.AliasNode, Alias: head}
	}
	return head, target
}

// resolveAlias gives up on a chain longer than maxAliasHops instead of
// following it: a missing bound turns the self-alias into an endless loop,
// which a test run in-process could not recover from, so each case runs in a
// child process (runIsolated, which also fails a hang). The should-pass cases
// are a plain node, one alias, and a chain of exactly maxAliasHops links; the
// should-fire cases are a self-alias and a chain one link too long.
func TestResolveAliasHopBound(t *testing.T) {
	t.Run("self alias", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			n := &yaml.Node{Kind: yaml.AliasNode}
			n.Alias = n
			if got := resolveAlias(n); got != nil {
				t.Fatalf("resolveAlias(self alias) = %+v; want nil", got)
			}
		})
	})
	t.Run("chain one longer than the bound", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			head, _ := aliasChain(maxAliasHops + 1)
			if got := resolveAlias(head); got != nil {
				t.Fatalf("resolveAlias(%d-link chain) = %+v; want nil", maxAliasHops+1, got)
			}
		})
	})
	t.Run("chain of exactly the bound", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			head, target := aliasChain(maxAliasHops)
			if got := resolveAlias(head); got != target {
				t.Fatalf("resolveAlias(%d-link chain) = %+v; want the scalar it names", maxAliasHops, got)
			}
		})
	})
	t.Run("short chain", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			head, target := aliasChain(3)
			if got := resolveAlias(head); got != target {
				t.Fatalf("resolveAlias(3-link chain) = %+v; want the scalar it names", got)
			}
		})
	})
	t.Run("not an alias and nil", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			_, target := aliasChain(0)
			if got := resolveAlias(target); got != target {
				t.Fatalf("resolveAlias(scalar) = %+v; want the scalar", got)
			}
			if got := resolveAlias(nil); got != nil {
				t.Fatalf("resolveAlias(nil) = %+v; want nil", got)
			}
		})
	})
}
