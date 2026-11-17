package inventory

import "go.yaml.in/yaml/v3"

// A YAML node is not always judged by its own tag. Ansible's !unsafe marks the
// whole value it tags — every string below it — as text that is never
// templated, so password.initial: "{{ x }}" under `users: !unsafe` (or under a
// user, or under `password:`, or in a document that is `--- !unsafe` as a
// whole) is the literal text {{ x }}, not a reference.
//
// The loader builds the objects of a document once per node: an alias, and a
// merge key (<<: *anchor), reuse the object built for the node they name. A
// scalar shared between a part that is !unsafe and a part that is not is
// therefore either templated or literal depending on which part the loader
// built first, and that order depends on the document's shape (a
// breadth-first deferral of mapping contents, verified against ansible-core
// 2.19.2 by TestAnsibleTagsMatchTheClassifier). Only the nodes that are
// reachable from an !unsafe node alone, or from the trusted part alone, have
// one answer; the shared ones have none that can be computed from the text.
//
// yamlTrust answers that per node, once per parsed document, in time linear in
// the document:
//
//   - unsafe holds every node reachable, through Content or an alias, from a
//     node tagged !unsafe (the tagged node included);
//   - trusted holds every node reachable from the document root without
//     entering an !unsafe node, except that the value of a merge key (<<) is
//     entered whatever its tag: the loader flattens a merge by taking the
//     source mapping's pairs without running the source node's own
//     constructor, so a source tagged !unsafe still hands its children to
//     the consumer as ordinary values.
//
// A node only in unsafe is literal; one in both is ambiguous; one only in
// trusted (or in neither: a node not part of the document) is judged by its
// own value as before.
type yamlTrust struct {
	unsafe  map[*yaml.Node]bool
	trusted map[*yaml.Node]bool
}

// newYAMLTrust computes the trust map of the parsed document doc. The walk
// visits every node at most once per set, so a document with shared anchors
// (merge fan-out) stays linear; parseYAMLDocument has already refused a cycle.
func newYAMLTrust(doc *yaml.Node) *yamlTrust {
	t := &yamlTrust{unsafe: map[*yaml.Node]bool{}, trusted: map[*yaml.Node]bool{}}
	if doc == nil {
		return t
	}

	var markUnsafe func(n *yaml.Node)
	markUnsafe = func(n *yaml.Node) {
		if n == nil || t.unsafe[n] {
			return
		}
		t.unsafe[n] = true
		if n.Kind == yaml.AliasNode {
			markUnsafe(n.Alias)
		}
		for _, c := range n.Content {
			markUnsafe(c)
		}
	}
	seen := map[*yaml.Node]bool{}
	var findUnsafe func(n *yaml.Node)
	findUnsafe = func(n *yaml.Node) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		if n.ShortTag() == "!unsafe" {
			markUnsafe(n)
		}
		if n.Kind == yaml.AliasNode {
			findUnsafe(n.Alias)
		}
		for _, c := range n.Content {
			findUnsafe(c)
		}
	}
	findUnsafe(doc)

	var enter func(n *yaml.Node, forced bool)
	var enterMergeValue, enterMergeSource func(n *yaml.Node)
	// enter marks n trusted and walks its children; an !unsafe node is skipped
	// unless forced (a merge source).
	enter = func(n *yaml.Node, forced bool) {
		if n == nil || t.trusted[n] {
			return
		}
		if !forced && n.ShortTag() == "!unsafe" {
			return
		}
		t.trusted[n] = true
		if n.Kind == yaml.AliasNode {
			enter(n.Alias, false)
			return
		}
		if n.Kind != yaml.MappingNode {
			for _, c := range n.Content {
				enter(c, false)
			}
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			enter(key, false)
			if key.ShortTag() == "!!merge" {
				enterMergeValue(value)
				continue
			}
			enter(value, false)
		}
	}
	// A merge key's value is an alias, a mapping, or a sequence of them.
	enterMergeValue = func(v *yaml.Node) {
		if v == nil {
			return
		}
		if v.Kind == yaml.AliasNode {
			t.trusted[v] = true
			enterMergeSource(v.Alias)
			return
		}
		enterMergeSource(v)
	}
	enterMergeSource = func(s *yaml.Node) {
		if s == nil {
			return
		}
		if s.Kind == yaml.SequenceNode {
			t.trusted[s] = true
			for _, item := range s.Content {
				enterMergeValue(item)
			}
			return
		}
		enter(s, true)
	}
	enter(doc, false)
	return t
}

// classify is what the trust map says about the template-looking scalar n.
func (t *yamlTrust) classify(n *yaml.Node) (literal, ambiguous bool) {
	if t == nil || !t.unsafe[n] {
		return false, false
	}
	if t.trusted[n] {
		return false, true
	}
	return true, false
}
