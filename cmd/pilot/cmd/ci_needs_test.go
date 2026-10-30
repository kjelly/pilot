// ci_needs_test.go covers the order of CI's jobs (.github/workflows/ci.yml).
//
// The image job publishes ghcr.io/kjelly/pilot-cli:sha-<short> on a main
// push, and the promote job moves :latest to it. Neither may happen while
// any validation job — Go tests, playbook lint, the root-only ownership
// tests, lint — is red or still running, so every one of them must be an
// ancestor of image. The image job's needs list was written by hand when the
// jobs were few; the root-tests job (PR #148) was added without it, and a
// push to main could then publish an image and move :latest while root-tests
// failed. A job added later would drift the same way.
package cmd

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type ciNeedsWorkflow struct {
	Jobs map[string]struct {
		Needs           any
		If              string `yaml:"if"`
		ContinueOnError any    `yaml:"continue-on-error"`
	}
}

// ciNeedsList is a job's needs as a list: GitHub accepts a string or a list.
func ciNeedsList(needs any) []string {
	switch v := needs.(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, n := range v {
			out = append(out, fmt.Sprint(n))
		}
		return out
	}
	return []string{fmt.Sprint(needs)}
}

// checkCIImageNeeds reports why a push to main can publish the image or move
// :latest before every validation job has passed, or "" when it cannot. The
// jobs are found by role, not by name: promote is the job that moves :latest
// (latestWriters), image the job it needs that builds the image
// (docker/build-push-action), and validation jobs are all the others — except
// those that run after image, which cannot be its dependencies.
func checkCIImageNeeds(ciYAML string) string {
	var wf ciImageWorkflow
	var nw ciNeedsWorkflow
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return "parse ci.yml: " + err.Error()
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &nw); err != nil {
		return "parse ci.yml: " + err.Error()
	}
	writers, _ := latestWriters(wf)
	if len(writers) != 1 {
		return fmt.Sprintf("steps that move :latest: %v, want exactly 1", writers)
	}
	promote, _, _ := strings.Cut(writers[0], "/")

	// ancestors is every job name reachable through needs from job, job
	// excluded; an unknown name is an error, not a skipped edge.
	var unknown string
	ancestors := func(job string) map[string]bool {
		seen := map[string]bool{}
		var walk func(string)
		walk = func(j string) {
			for _, n := range ciNeedsList(nw.Jobs[j].Needs) {
				if _, ok := nw.Jobs[n]; !ok {
					unknown = fmt.Sprintf("job %s needs unknown job %q", j, n)
					continue
				}
				if !seen[n] {
					seen[n] = true
					walk(n)
				}
			}
		}
		walk(job)
		return seen
	}

	var builders []string
	promoteDeps := ancestors(promote)
	for name := range promoteDeps {
		for _, st := range wf.Jobs[name].Steps {
			if strings.HasPrefix(st.Uses, "docker/build-push-action@") {
				builders = append(builders, name)
				break
			}
		}
	}
	if unknown != "" {
		return unknown
	}
	if len(builders) != 1 {
		return fmt.Sprintf("job %s moves :latest but needs %v, which build the image: want exactly 1 (a docker/build-push-action job)", promote, builders)
	}
	image := builders[0]
	imageDeps := ancestors(image)
	if unknown != "" {
		return unknown
	}

	var names []string
	for name := range nw.Jobs {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if name == image || name == promote || ancestors(name)[image] || ancestors(name)[promote] {
			continue
		}
		job := nw.Jobs[name]
		switch {
		case !imageDeps[name]:
			return fmt.Sprintf("%s does not (transitively) need %s", image, name)
		case job.If != "":
			return fmt.Sprintf("validation job %s has if: %q; when it is skipped, the jobs that need it are skipped too, and when it is not run a failure does not stop %s", name, job.If, image)
		case job.ContinueOnError != nil && fmt.Sprint(job.ContinueOnError) != "false":
			return fmt.Sprintf("validation job %s has continue-on-error: %v, so %s runs when it fails", name, job.ContinueOnError, image)
		}
	}
	if unknown != "" {
		return unknown
	}
	return ""
}

func TestCIImageWaitsForEveryValidationJob(t *testing.T) {
	if msg := checkCIImageNeeds(readCIYAML(t)); msg != "" {
		t.Fatal(msg)
	}
}

// Each way the image job's needs can drift fires, and the layouts that are
// right do not (AGENTS.md §5.12).
func TestCIImageNeedsCheckCatchesDrift(t *testing.T) {
	ci := readCIYAML(t)
	edit := func(old, new string) string {
		t.Helper()
		if !strings.Contains(ci, old) {
			t.Fatalf("ci.yml no longer contains %q; update this test", old)
		}
		return strings.Replace(ci, old, new, 1)
	}
	const imageNeeds = "    needs: [test, playbook-lint, root-tests, thanos-retention, lint, pilot-mcp-cross]\n"
	cases := []struct{ name, ci, want string }{
		{"current", ci, ""},
		{"transitive path through another job", strings.Replace(edit(imageNeeds, "    needs: [test, playbook-lint, thanos-retention, lint, pilot-mcp-cross]\n"), "  lint:\n", "  lint:\n    needs: root-tests\n", 1), ""},
		{"image needs one job as a string", strings.Replace(edit(imageNeeds, "    needs: lint\n"), "  lint:\n", "  lint:\n    needs: [test, playbook-lint, root-tests, thanos-retention, pilot-mcp-cross]\n", 1), ""},
		{"promote lists image", edit("    needs: image\n", "    needs: [image]\n"), ""},
		// The state of main after PR #148 added root-tests.
		{"root-tests missing", edit(imageNeeds, "    needs: [test, playbook-lint, thanos-retention, lint, pilot-mcp-cross]\n"), "image does not (transitively) need root-tests"},
		{"test missing", edit(imageNeeds, "    needs: [playbook-lint, root-tests, thanos-retention, lint, pilot-mcp-cross]\n"), "image does not (transitively) need test"},
		{"a new job omitted", ci + "\n  docs:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo docs\n", "image does not (transitively) need docs"},
		{"a new job after image is not a dependency", ci + "\n  notify:\n    needs: promote\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo notify\n", ""},
		{"promote does not need image", edit("    needs: image\n", "    needs: test\n"), "want exactly 1"},
		{"unknown needs name", edit(imageNeeds, "    needs: [test, playbook-lint, root-tests, thanos-retention, lint, pilot-mcp-cross, roots-tests]\n"), `unknown job "roots-tests"`},
		{"validation job with if", strings.Replace(ci, "  root-tests:\n", "  root-tests:\n    if: github.event_name == 'push'\n", 1), "validation job root-tests has if:"},
		{"validation job continue-on-error", strings.Replace(ci, "  root-tests:\n", "  root-tests:\n    continue-on-error: true\n", 1), "validation job root-tests has continue-on-error"},
		{"continue-on-error false", strings.Replace(ci, "  root-tests:\n", "  root-tests:\n    continue-on-error: false\n", 1), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIImageNeeds(tc.ci)
			if tc.want == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, got)
			}
		})
	}
}
