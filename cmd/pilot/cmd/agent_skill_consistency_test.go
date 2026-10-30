// agent_skill_consistency_test.go guards the project-local agent skill
// layout, which records the same thing in several places (AGENTS.md §5.7:
// such pairs need a single source or a consistency test).
//
//   - .agents/skills/<skill>/ is the canonical skill directory (Codex reads
//     it). Claude Code reads only .claude/skills/, so every skill needs a
//     symlink there or Claude never sees it. On 2026-10-30 only 3 of the 11
//     project skills were linked.
//   - Each native role prompt exists once per platform under
//     platforms/{codex,claude,agy}/agents/. The prompt bodies must be
//     identical; the agy copies had drifted by 4–9 lines (the pilot-specific
//     instructions were added to claude/codex only) when this test was
//     written.
//   - Codex reads .codex/agents/<role>.toml, which install.sh copies from the
//     skill; Claude Code reads .claude/agents/<role>.md, a symlink to the
//     skill's claude file. Both have to stay in step with the skill.
//
// TestAgentSkillLayoutCheckCatchesDrift puts each of those regressions into
// a synthetic tree and asserts the check reports it.
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var tomlDeveloperInstructionsRE = regexp.MustCompile(`(?s)developer_instructions\s*=\s*"""\n?(.*?)"""`)

// agentSkillLayoutProblems checks the project-local agent skill layout under
// root and returns one entry per problem; an empty result means consistent.
func agentSkillLayoutProblems(root string) ([]string, error) {
	var problems []string
	rel := func(p string) string {
		if r, err := filepath.Rel(root, p); err == nil {
			return r
		}
		return p
	}
	linksTo := func(link, want string) string {
		fi, err := os.Lstat(link)
		if err != nil {
			return fmt.Sprintf("%s: missing; create a relative symlink to %s", rel(link), rel(want))
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Sprintf("%s: is a copy, not a symlink to %s", rel(link), rel(want))
		}
		got, err := filepath.EvalSymlinks(link)
		if err != nil {
			return fmt.Sprintf("%s: dangling symlink (%v)", rel(link), err)
		}
		wantReal, err := filepath.EvalSymlinks(want)
		if err != nil {
			return fmt.Sprintf("%s: target %s: %v", rel(link), rel(want), err)
		}
		if got != wantReal {
			return fmt.Sprintf("%s: points at %s, want %s", rel(link), rel(got), rel(want))
		}
		return ""
	}

	skillsDir := filepath.Join(root, ".agents", "skills")
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil, err
	}
	var skills []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(skillsDir, e.Name(), "SKILL.md")); err == nil {
			skills = append(skills, e.Name())
		}
	}
	if len(skills) == 0 {
		return nil, fmt.Errorf("no skill (directory with SKILL.md) under %s", rel(skillsDir))
	}
	sort.Strings(skills)
	isSkill := map[string]bool{}
	for _, s := range skills {
		isSkill[s] = true
	}

	claudeSkills := filepath.Join(root, ".claude", "skills")
	for _, name := range skills {
		if p := linksTo(filepath.Join(claudeSkills, name), filepath.Join(skillsDir, name)); p != "" {
			problems = append(problems, p)
		}
	}
	if entries, err := os.ReadDir(claudeSkills); err == nil {
		for _, e := range entries {
			if !isSkill[e.Name()] {
				problems = append(problems, fmt.Sprintf("%s: not a project skill (stray file or dangling link)", rel(filepath.Join(claudeSkills, e.Name()))))
			}
		}
	}

	claudeAgents := filepath.Join(root, ".claude", "agents")
	expectedAgents := map[string]bool{}
	for _, name := range skills {
		platforms := filepath.Join(skillsDir, name, "platforms")
		claudeDir := filepath.Join(platforms, "claude", "agents")
		roles, err := os.ReadDir(claudeDir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, r := range roles {
			if !strings.HasSuffix(r.Name(), ".md") {
				continue
			}
			role := strings.TrimSuffix(r.Name(), ".md")
			claudeFile := filepath.Join(claudeDir, r.Name())
			want, err := markdownBody(claudeFile)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", rel(claudeFile), err))
				continue
			}

			agyFile := filepath.Join(platforms, "agy", "agents", role+".md")
			if got, err := markdownBody(agyFile); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", rel(agyFile), err))
			} else if got != want {
				problems = append(problems, fmt.Sprintf("%s: prompt differs from %s:\n%s", rel(agyFile), rel(claudeFile), promptDiff(want, got)))
			}

			codexFile := filepath.Join(platforms, "codex", "agents", role+".toml")
			codexData, err := os.ReadFile(codexFile)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", rel(codexFile), err))
			} else {
				if m := tomlDeveloperInstructionsRE.FindSubmatch(codexData); m == nil {
					problems = append(problems, fmt.Sprintf("%s: no developer_instructions = \"\"\"...\"\"\" block", rel(codexFile)))
				} else if got := strings.TrimSpace(string(m[1])); got != want {
					problems = append(problems, fmt.Sprintf("%s: developer_instructions differ from %s:\n%s", rel(codexFile), rel(claudeFile), promptDiff(want, got)))
				}
				installed := filepath.Join(root, ".codex", "agents", role+".toml")
				if data, err := os.ReadFile(installed); err != nil {
					problems = append(problems, fmt.Sprintf("%s: %v; Codex reads .codex/agents, copy %s there", rel(installed), err, rel(codexFile)))
				} else if !bytes.Equal(data, codexData) {
					problems = append(problems, fmt.Sprintf("%s: differs from %s; re-copy it", rel(installed), rel(codexFile)))
				}
			}

			if p := linksTo(filepath.Join(claudeAgents, role+".md"), claudeFile); p != "" {
				problems = append(problems, p)
			}
			expectedAgents[role+".md"] = true
		}
	}
	if entries, err := os.ReadDir(claudeAgents); err == nil {
		for _, e := range entries {
			if !expectedAgents[e.Name()] {
				problems = append(problems, fmt.Sprintf("%s: not a link to a project skill's platforms/claude/agents file", rel(filepath.Join(claudeAgents, e.Name()))))
			}
		}
	}
	return problems, nil
}

// markdownBody returns the trimmed text after the YAML frontmatter of an
// agent definition file.
func markdownBody(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := string(data)
	if !strings.HasPrefix(s, "---\n") {
		return "", fmt.Errorf("no YAML frontmatter")
	}
	rest := s[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return "", fmt.Errorf("unterminated YAML frontmatter")
	}
	return strings.TrimSpace(rest[end+len("\n---\n"):]), nil
}

// promptDiff lists the lines present in only one of two prompt bodies.
func promptDiff(want, got string) string {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, line := range strings.Split(s, "\n") {
			m[line]++
		}
		return m
	}
	w, g := count(want), count(got)
	var out []string
	for _, line := range strings.Split(want, "\n") {
		if g[line] < w[line] {
			out = append(out, "  - "+line)
			g[line]++
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if w[line] < g[line] {
			out = append(out, "  + "+line)
			w[line]++
		}
	}
	return strings.Join(out, "\n")
}

func TestAgentSkillLayoutIsConsistent(t *testing.T) {
	problems, err := agentSkillLayoutProblems(repoRootForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// writeAgentSkillFixture builds one skill with one role across the three
// platforms plus the installed Codex copy and the Claude symlinks.
func writeAgentSkillFixture(t *testing.T, root, skill, role, prompt string) {
	t.Helper()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		relTarget, err := filepath.Rel(filepath.Dir(path), target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(relTarget, path); err != nil {
			t.Fatal(err)
		}
	}
	skillDir := filepath.Join(root, ".agents", "skills", skill)
	write(filepath.Join(skillDir, "SKILL.md"), "---\nname: "+skill+"\n---\n\n# "+skill+"\n")
	md := "---\nname: " + role + "\nmodel: sonnet\n---\n\n" + prompt + "\n"
	write(filepath.Join(skillDir, "platforms", "claude", "agents", role+".md"), md)
	write(filepath.Join(skillDir, "platforms", "agy", "agents", role+".md"), "---\nname: "+role+"\nmodel: inherit\n---\n\n"+prompt+"\n")
	toml := "name = \"" + role + "\"\nmodel = \"x\"\ndeveloper_instructions = \"\"\"\n" + prompt + "\n\"\"\"\n"
	write(filepath.Join(skillDir, "platforms", "codex", "agents", role+".toml"), toml)
	write(filepath.Join(root, ".codex", "agents", role+".toml"), toml)
	link(skillDir, filepath.Join(root, ".claude", "skills", skill))
	link(filepath.Join(skillDir, "platforms", "claude", "agents", role+".md"), filepath.Join(root, ".claude", "agents", role+".md"))
}

func TestAgentSkillLayoutCheckCatchesDrift(t *testing.T) {
	const prompt = "You are Role.\nDo the assigned thing only."
	cases := []struct {
		name   string
		drift  func(t *testing.T, root string)
		report string
	}{
		{"agy prompt drifts", func(t *testing.T, root string) {
			path := filepath.Join(root, ".agents", "skills", "one", "platforms", "agy", "agents", "role.md")
			if err := os.WriteFile(path, []byte("---\nname: role\n---\n\nYou are Role.\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "platforms/agy/agents/role.md: prompt differs"},
		{"codex prompt drifts", func(t *testing.T, root string) {
			path := filepath.Join(root, ".agents", "skills", "one", "platforms", "codex", "agents", "role.toml")
			if err := os.WriteFile(path, []byte("name = \"role\"\ndeveloper_instructions = \"\"\"\nYou are Role.\n\"\"\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "platforms/codex/agents/role.toml: developer_instructions differ"},
		{"installed codex copy stale", func(t *testing.T, root string) {
			path := filepath.Join(root, ".codex", "agents", "role.toml")
			if err := os.WriteFile(path, []byte("name = \"role\"\ndeveloper_instructions = \"\"\"\nold\n\"\"\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, ".codex/agents/role.toml: differs from"},
		{"installed codex copy missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, ".codex", "agents", "role.toml")); err != nil {
				t.Fatal(err)
			}
		}, ".codex/agents/role.toml: open"},
		{"claude skill link missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, ".claude", "skills", "one")); err != nil {
				t.Fatal(err)
			}
		}, ".claude/skills/one: missing"},
		{"claude skill is a copy", func(t *testing.T, root string) {
			path := filepath.Join(root, ".claude", "skills", "one")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}, ".claude/skills/one: is a copy"},
		{"claude skill link dangles", func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, ".agents", "skills", "two")); err != nil {
				t.Fatal(err)
			}
		}, ".claude/skills/two: not a project skill"},
		{"claude agent link missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, ".claude", "agents", "role.md")); err != nil {
				t.Fatal(err)
			}
		}, ".claude/agents/role.md: missing"},
		{"stray claude agent", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, ".claude", "agents", "extra.md"), []byte("---\nname: extra\n---\n\nx\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, ".claude/agents/extra.md: not a link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeAgentSkillFixture(t, root, "one", "role", prompt)
			writeAgentSkillFixture(t, root, "two", "other", prompt)
			if problems, err := agentSkillLayoutProblems(root); err != nil || len(problems) != 0 {
				t.Fatalf("clean fixture must pass: err=%v problems=%q", err, problems)
			}
			tc.drift(t, root)
			problems, err := agentSkillLayoutProblems(root)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.report) {
				t.Fatalf("want a problem containing %q, got %q", tc.report, problems)
			}
		})
	}
}
