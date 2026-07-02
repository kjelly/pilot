// Query expansion for LLM retrieval. Three layers:
//
//  1. Synonym expansion: LLM asks "how to restart" → we add
//     "state restarted" to the recall so the state parameter wins.
//  2. Intent detection: phrases like "how to enable service at boot"
//     map to a known param_name + module combination via intent rules.
//     More specific than plain synonym expansion; takes precedence.
//  3. Param-name hints: if the query already contains a known
//     parameter name (e.g. "enabled", "mode"), do not expand —
//     the original word is already the best signal.
//
// Each layer is unit-tested in llm_query_expand_test.go.

package docs

import (
	"sort"
	"strings"
)

// IntentRule maps a query phrase to a (module_short, param_name) pair
// the LLM is most likely after. The match is case-insensitive substring.
// On hit, the rule boosts the corresponding chunk in the result set.
type IntentRule struct {
	Phrase    string // "restart" or "restart service"
	ParamName string // "state"
	Module    string // "service" (empty = any module)
	Boost     float64
}

// intentRules is hand-curated from observed LLM usage. Order doesn't
// matter — we score by Boost and pick the strongest match.
var intentRules = []IntentRule{
	// service-related
	{Phrase: "at boot", ParamName: "enabled", Module: "service", Boost: 3.0},
	{Phrase: "start at boot", ParamName: "enabled", Module: "service", Boost: 3.0},
	{Phrase: "autostart", ParamName: "enabled", Module: "service", Boost: 3.0},
	{Phrase: "boot enabled", ParamName: "enabled", Module: "service", Boost: 3.0},
	{Phrase: "restart", ParamName: "state", Module: "service", Boost: 2.5},
	{Phrase: "reload", ParamName: "state", Module: "service", Boost: 2.5},
	{Phrase: "stop service", ParamName: "state", Module: "service", Boost: 2.5},
	{Phrase: "start service", ParamName: "state", Module: "service", Boost: 2.0},

	// package-related
	{Phrase: "install package", ParamName: "state", Module: "package", Boost: 2.5},
	{Phrase: "remove package", ParamName: "state", Module: "package", Boost: 2.5},
	{Phrase: "update package", ParamName: "state", Module: "package", Boost: 2.0},
	{Phrase: "package cache", ParamName: "update_cache", Module: "apt", Boost: 2.5},

	// file-related
	{Phrase: "permissions", ParamName: "mode", Module: "file", Boost: 2.5},
	{Phrase: "chmod", ParamName: "mode", Module: "file", Boost: 2.5},
	{Phrase: "owner", ParamName: "owner", Module: "file", Boost: 2.0},
	{Phrase: "set mode", ParamName: "mode", Module: "file", Boost: 2.5},

	// lineinfile / sshd_config style
	{Phrase: "change a line", ParamName: "line", Module: "lineinfile", Boost: 2.0},
	{Phrase: "match a line", ParamName: "regexp", Module: "lineinfile", Boost: 2.0},
	{Phrase: "regex match", ParamName: "regexp", Module: "lineinfile", Boost: 2.0},

	// user-related
	{Phrase: "create user", ParamName: "name", Module: "user", Boost: 1.5},
	{Phrase: "set password", ParamName: "password", Module: "user", Boost: 2.5},
	{Phrase: "add user", ParamName: "name", Module: "user", Boost: 1.5},

	// network / firewall
	{Phrase: "open port", ParamName: "port", Module: "firewalld", Boost: 2.5},
	{Phrase: "allow port", ParamName: "port", Module: "firewalld", Boost: 2.5},
}

// IntentHit is what an intent rule produced. The search loop uses this
// to apply per-chunk boosts after the BM25 pass.
type IntentHit struct {
	ParamName string
	Module    string
	Boost     float64
	Phrase    string
}

// ExpandQuery applies synonym + intent expansion to a raw LLM query.
// Returns:
//   - expandedQuery: terms to add to the recall (concatenated into a
//     disjunction). May be empty if no expansion triggered.
//   - intents: per-chunk boost targets. Search code applies these in
//     the post-rank layer.
//
// expand(original) is idempotent: passing an already-expanded query
// produces the same intents.
func ExpandQuery(original string) (expandedQuery string, intents []IntentHit) {
	q := strings.ToLower(strings.TrimSpace(original))
	if q == "" {
		return "", nil
	}

	// Intent detection first; strong matches are recorded for boost.
	intents = matchIntents(q)

	// Synonym expansion: for each token in the query that we have
	// synonyms for, add the synonyms to the recall. Tokens are space-
	// separated. We skip tokens that look like param names already
	// (a known param_name should not be expanded).
	tokens := tokenizeForExpansion(q)
	expansions := make(map[string]bool, len(tokens))
	for _, tok := range tokens {
		if isLikelyParamName(tok) {
			continue
		}
		for _, syn := range synonymsForToken(tok) {
			if syn != tok {
				expansions[syn] = true
			}
		}
	}

	// Build the expanded query: original + collected synonyms. We
	// dedupe against the original tokens so we don't double-up.
	origTokens := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		origTokens[t] = true
	}
	var parts []string
	parts = append(parts, tokens...)
	var keys []string
	for k := range expansions {
		if !origTokens[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts = append(parts, keys...)

	if len(parts) > len(tokens) {
		expandedQuery = strings.Join(parts, " ")
	} else {
		// No new terms added this pass. Preserve the input so re-
		// expanding an already-expanded query is stable (idempotent
		// up to the first pass).
		expandedQuery = strings.TrimSpace(original)
	}
	return expandedQuery, intents
}

// matchIntents scans intent rules and returns the strongest match per
// (param, module). Multiple phrase matches in the same query still
// produce one intent; we keep the highest boost.
func matchIntents(q string) []IntentHit {
	bestByKey := make(map[string]*IntentHit)
	for _, r := range intentRules {
		if r.Module != "" && !strings.Contains(q, r.Module) && !phraseMatches(q, r) {
			continue
		}
		if !strings.Contains(q, r.Phrase) {
			continue
		}
		key := r.ParamName + "|" + r.Module
		if existing, ok := bestByKey[key]; ok {
			if r.Boost > existing.Boost {
				existing.Boost = r.Boost
				existing.Phrase = r.Phrase
			}
			continue
		}
		h := IntentHit{
			ParamName: r.ParamName,
			Module:    r.Module,
			Boost:     r.Boost,
			Phrase:    r.Phrase,
		}
		bestByKey[key] = &h
	}
	out := make([]IntentHit, 0, len(bestByKey))
	for _, h := range bestByKey {
		out = append(out, *h)
	}
	return out
}

// phraseMatches decides whether an intent rule whose Module is set
// can fire on a query that doesn't contain the module name. This is
// intentionally lenient: "how to restart nginx" matches the
// "restart" → state rule even though "service" isn't in the query.
func phraseMatches(q string, r IntentRule) bool {
	return strings.Contains(q, r.Phrase)
}

// synonymsForToken is the synonym table itself. Centralised here so
// it's easy to extend without touching the intent layer.
func synonymsForToken(tok string) []string {
	switch tok {
	case "restart", "reboot", "bounce":
		return []string{"state", "restarted", "reload"}
	case "stop", "halt", "disable":
		return []string{"state", "stopped"}
	case "start", "launch", "enable", "boot":
		return []string{"enabled", "started", "boot"}
	case "permissions", "chmod", "perm":
		return []string{"mode", "owner", "group"}
	case "install", "add":
		return []string{"present", "installed", "state"}
	case "remove", "uninstall", "delete":
		return []string{"absent", "removed", "state"}
	case "owner":
		return []string{"owner", "user"}
	case "user":
		return []string{"name", "uid"}
	case "port":
		return []string{"port", "destination"}
	case "password", "passwd":
		return []string{"password"}
	case "regex", "regexp", "pattern":
		return []string{"regexp", "regex"}
	}
	return nil
}

// paramNamesNotToExpand is the set of well-known ansible parameter
// names we treat as "perfect signal" — synonym expansion would only
// dilute them. Anything NOT in this set (e.g. verbs like "restart",
// "enable", "install") is eligible for synonym expansion.
var paramNamesNotToExpand = map[string]bool{
	"enabled": true, "state": true, "name": true, "use": true,
	"daemon_reload": true, "pkg": true, "package": true,
	"update_cache": true, "src": true, "dest": true, "path": true,
	"mode": true, "owner": true, "group": true, "content": true,
	"force": true, "backup": true, "follow": true,
	"regexp": true, "line": true, "insertafter": true,
	"insertbefore": true, "create": true,
	"uid": true, "gid": true, "shell": true, "home": true,
	"password": true, "groups": true, "append": true, "system": true,
	"remove": true, "expires": true,
	"chain": true, "source": true, "destination": true,
	"protocol": true, "jump": true, "comment": true,
	"become": true, "become_user": true, "ignore_errors": true,
	"register": true, "when": true, "loop": true,
	"with_items": true, "tags": true, "notify": true,
	"delegate_to": true, "run_once": true,
}

// isLikelyParamName returns true if tok is a known ansible parameter
// name we should NOT synonym-expand.
func isLikelyParamName(tok string) bool {
	if tok == "" || len(tok) > 32 {
		return false
	}
	if len(tok) < 2 {
		return false
	}
	return paramNamesNotToExpand[tok]
}

func tokenizeForExpansion(q string) []string {
	var out []string
	var cur strings.Builder
	for _, r := range q {
		if r == ' ' || r == '\t' || r == '\n' || r == ',' || r == ';' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ApplyIntentBoosts walks the in-rank hits and multiplies scores
// when a chunk's (ref, param_name) matches an intent. Returns a new
// slice; original is not mutated.
func ApplyIntentBoosts(matches []Match, idx *ModuleIndex, intents []IntentHit) []Match {
	if len(intents) == 0 || idx == nil {
		return matches
	}
	// Index intents by (param, module_short) for O(1) lookup.
	type key struct {
		param, module string
	}
	boosts := make(map[key]float64, len(intents))
	for _, h := range intents {
		k := key{param: h.ParamName, module: h.Module}
		if existing, ok := boosts[k]; ok {
			if h.Boost > existing {
				boosts[k] = h.Boost
			}
		} else {
			boosts[k] = h.Boost
		}
	}
	out := make([]Match, len(matches))
	for i, m := range matches {
		c := idx.ChunkByIndex(m.Index)
		// Compare against short module name (without collection prefix).
		shortModule := c.Ref
		if idx := strings.LastIndex(shortModule, "."); idx >= 0 {
			shortModule = shortModule[idx+1:]
		}
		pn, _ := c.Metadata["param_name"].(string)
		k := key{param: pn, module: shortModule}
		// Intent rule might not specify module — match by param alone.
		k2 := key{param: pn, module: ""}
		boost := boosts[k]
		if boosts[k2] > boost {
			boost = boosts[k2]
		}
		if boost > 0 {
			out[i] = Match{Index: m.Index, Score: m.Score * boost}
		} else {
			out[i] = m
		}
	}
	return out
}
