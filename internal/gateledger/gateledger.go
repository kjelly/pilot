// Package gateledger is test support for fail-closed code: it lists the
// return statements of chosen functions that return something other than a
// literal nil (a "gate": the function refuses and says why), and checks that
// each one is named in the source and has a test row that makes it fire.
//
// A gate is named by a comment on the return's line (or the line above it):
//
//	return fmt.Errorf("--limit 不能含空白") // gate: limit-blank
//
// A test row names the gates it makes fire in a composite literal's gate
// field, ids separated by commas:
//
//	{name: "blank limit", args: ..., gate: "limit-blank"}
//
// Check then fails when a return has no name, two returns share one, a gate
// has neither a row nor an exemption (with its reason), an exemption has
// become stale, or a row names a gate no return carries. The point is
// AGENTS.md §5.12: deleting a gate must fail a test, so a new gate cannot
// land without a row. The package holds no production logic and is imported
// by tests only.
package gateledger

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Return is one return statement of a scanned function that does not end in
// a literal nil.
type Return struct {
	File string
	Func string
	Line int
	Src  string // the return's first line, trimmed
	Gate string // the id from the gate comment; empty when there is none
}

// Result is what Scan found.
type Result struct {
	Returns []Return
	// Stray lists "file:line" of gate comments inside a scanned function that
	// are not on, or directly above, a counted return.
	Stray []string
}

// Scan parses filename (src, when not nil, replaces its content) and lists
// the non-nil returns of the named top-level functions. Returns inside a
// nested function literal belong to that closure and are not listed. A
// function that is not in the file is an error: a renamed gate holder must
// not make the check pass by scanning nothing.
func Scan(filename string, src []byte, funcs ...string) (Result, error) {
	fset := token.NewFileSet()
	var in any
	if src != nil {
		in = src
	}
	file, err := parser.ParseFile(fset, filename, in, parser.ParseComments)
	if err != nil {
		return Result{}, err
	}
	if src == nil {
		if src, err = os.ReadFile(filename); err != nil {
			return Result{}, err
		}
	}
	lines := strings.Split(string(src), "\n")

	// The gate comments by line.
	gateAt := map[int]string{}
	for _, group := range file.Comments {
		for _, c := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			if id, ok := strings.CutPrefix(text, "gate:"); ok {
				gateAt[fset.Position(c.Pos()).Line] = strings.TrimSpace(id)
			}
		}
	}

	var res Result
	used := map[int]bool{}
	wanted := map[string]bool{}
	for _, f := range funcs {
		wanted[f] = true
	}
	found := map[string]bool{}
	var spans [][2]int
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || !wanted[fd.Name.Name] || fd.Body == nil {
			continue
		}
		found[fd.Name.Name] = true
		spans = append(spans, [2]int{fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line})
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			if len(ret.Results) > 0 {
				if id, ok := ret.Results[len(ret.Results)-1].(*ast.Ident); ok && id.Name == "nil" {
					return true
				}
			}
			start, end := fset.Position(ret.Pos()).Line, fset.Position(ret.End()).Line
			r := Return{File: filename, Func: fd.Name.Name, Line: start, Src: strings.TrimSpace(lines[start-1])}
			for line := start - 1; line <= end && r.Gate == ""; line++ {
				id, ok := gateAt[line]
				if !ok || used[line] {
					continue
				}
				// The line above counts only when the comment stands alone:
				// a trailing comment there belongs to that line's statement.
				if line == start-1 && !strings.HasPrefix(strings.TrimSpace(lines[line-1]), "//") {
					continue
				}
				r.Gate = id
				used[line] = true
			}
			res.Returns = append(res.Returns, r)
			return true
		})
	}
	for _, f := range funcs {
		if !found[f] {
			return Result{}, fmt.Errorf("%s: function %s not found", filename, f)
		}
	}
	for line := range gateAt {
		if used[line] {
			continue
		}
		for _, span := range spans {
			if line >= span[0] && line <= span[1] {
				res.Stray = append(res.Stray, fmt.Sprintf("%s:%d", filename, line))
			}
		}
	}
	sort.Strings(res.Stray)
	return res, nil
}

// RowGates parses the Go files and returns, for each gate id named by a
// `gate: "<id>[,<id>...]"` field of a composite literal, how many rows name
// it. An empty gate is a row that is expected to pass.
func RowGates(files ...string) (map[string]int, error) {
	rows := map[string]int{}
	fset := token.NewFileSet()
	for _, name := range files {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "gate" {
				return true
			}
			lit, ok := kv.Value.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for id := range strings.SplitSeq(text, ",") {
				if id = strings.TrimSpace(id); id != "" {
					rows[id]++
				}
			}
			return true
		})
	}
	return rows, nil
}

// Check returns what is wrong with the ledger, one line per problem; none
// means every gate is named, unique, and has a row or a stated exemption.
// exempt maps a gate id to why it has no row.
func Check(res Result, rows map[string]int, exempt map[string]string) []string {
	var problems []string
	seen := map[string]Return{}
	for _, r := range res.Returns {
		where := fmt.Sprintf("%s:%d (%s)", r.File, r.Line, r.Func)
		switch {
		case r.Gate == "":
			problems = append(problems, fmt.Sprintf("%s: return without a `// gate: <id>` comment: %s", where, r.Src))
			continue
		case strings.ContainsAny(r.Gate, ", \t"):
			problems = append(problems, fmt.Sprintf("%s: gate id %q must be one word", where, r.Gate))
			continue
		}
		if prev, dup := seen[r.Gate]; dup {
			problems = append(problems, fmt.Sprintf("%s: gate %q is also at line %d", where, r.Gate, prev.Line))
			continue
		}
		seen[r.Gate] = r
		_, exempted := exempt[r.Gate]
		switch {
		case exempted && rows[r.Gate] > 0:
			problems = append(problems, fmt.Sprintf("%s: gate %q has a row now; drop its exemption", where, r.Gate))
		case !exempted && rows[r.Gate] == 0:
			problems = append(problems, fmt.Sprintf("%s: gate %q has no row (a test case that makes it fire) and no exemption", where, r.Gate))
		}
	}
	for id, reason := range exempt {
		if _, ok := seen[id]; !ok {
			problems = append(problems, fmt.Sprintf("exemption %q names no gate in the code", id))
		}
		if strings.TrimSpace(reason) == "" {
			problems = append(problems, fmt.Sprintf("exemption %q has no reason", id))
		}
	}
	for id := range rows {
		if _, ok := seen[id]; !ok {
			problems = append(problems, fmt.Sprintf("a test row names gate %q, which no return carries", id))
		}
	}
	for _, s := range res.Stray {
		problems = append(problems, s+": gate comment that is not on a counted return")
	}
	slices.Sort(problems)
	return problems
}
