// ci_image_test.go covers CI's pilot-cli image jobs (.github/workflows/ci.yml).
//
// ghcr.io/kjelly/pilot-cli:latest must never go back to an older commit. The
// image job pushes per-commit tags only; one step moves :latest, and it reads
// main's head and moves the tag inside a job that holds a concurrency lock
// every run shares. The first version decided :latest in the build job before
// a 3 min build: run A could see main at A, B could be merged and promote B,
// and A would still promote A afterwards (PR #144 review).
//
// The image job's build-args must match the Dockerfile's ARGs: Docker only
// warns about an unknown build-arg, and a renamed or new version ARG would
// otherwise ship release images stamped with its 0.0.0-dev default.
package cmd

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// latestWriteRE matches a shell line that writes the :latest tag.
var latestWriteRE = regexp.MustCompile(`(imagetools create|docker (tag|push))[^\n]*:latest`)

type ciImageWorkflow struct {
	Jobs map[string]struct {
		If          string `yaml:"if"`
		Needs       any
		Concurrency any
		Steps       []struct {
			Uses, Run string
			With      map[string]any
		}
	}
}

// latestWriters returns "job/step-index" for every step that writes :latest,
// and the run script of the last one.
func latestWriters(wf ciImageWorkflow) (writers []string, script string) {
	for _, name := range slices.Sorted(maps.Keys(wf.Jobs)) {
		for i, st := range wf.Jobs[name].Steps {
			if latestWriteRE.MatchString(st.Run) {
				writers = append(writers, fmt.Sprintf("%s/%d", name, i))
				script = st.Run
			}
		}
	}
	return writers, script
}

// checkCIImageLatest reports why ci.yml can move :latest to an older commit,
// or "" when it cannot.
func checkCIImageLatest(ciYAML string) string {
	var wf ciImageWorkflow
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return "parse ci.yml: " + err.Error()
	}
	for name, job := range wf.Jobs {
		for _, st := range job.Steps {
			tags := fmt.Sprint(st.With["tags"])
			switch {
			case strings.HasPrefix(st.Uses, "docker/metadata-action@"):
				if !strings.Contains(fmt.Sprint(st.With["flavor"]), "latest=false") {
					return "job " + name + ": metadata-action without flavor latest=false writes :latest on every semver tag"
				}
				if strings.Contains(tags, "value=latest") {
					return "job " + name + ": metadata-action decides :latest outside the locked promote step"
				}
			case strings.HasPrefix(st.Uses, "docker/build-push-action@"):
				if strings.Contains(tags, ":latest") {
					return "job " + name + ": build-push-action pushes :latest outside the locked promote step"
				}
			}
		}
	}
	writers, script := latestWriters(wf)
	if len(writers) != 1 {
		return fmt.Sprintf("steps that move :latest: %v, want exactly 1", writers)
	}
	name, _, _ := strings.Cut(writers[0], "/")
	job := wf.Jobs[name]
	if job.If != "github.repository == 'kjelly/pilot' && github.ref == 'refs/heads/main'" {
		return "job " + name + " moves :latest but runs for " + strconv.Quote(job.If) + ", want only main of kjelly/pilot"
	}
	if needs := fmt.Sprint(job.Needs); needs != "image" && needs != "[image]" {
		return "job " + name + " moves :latest but needs " + needs + ", want the image job whose digest it promotes"
	}
	c, _ := job.Concurrency.(map[string]any)
	group, _ := c["group"].(string)
	if group == "" || fmt.Sprint(c["cancel-in-progress"]) != "false" {
		return "job " + name + " moves :latest without a concurrency lock (a group with cancel-in-progress: false)"
	}
	if strings.Contains(group, "${{") {
		return "job " + name + ": concurrency group " + strconv.Quote(group) + " is not one lock shared by every run"
	}
	// The default queue (single) cancels a pending promote when another one
	// queues; if that one is an older commit it skips and :latest stays
	// behind main.
	if c["queue"] != "max" {
		return "job " + name + ": concurrency queue must be max, so no waiting promote is cancelled"
	}
	read := strings.Index(script, "git/ref/heads/main")
	write := latestWriteRE.FindStringIndex(script)
	if read < 0 || read > write[0] {
		return "job " + name + " must read main's head in the step that moves :latest, before moving it"
	}
	return ""
}

func readCIYAML(t *testing.T) string {
	t.Helper()
	ci, err := os.ReadFile(filepath.Join(repoRootForTest(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(ci)
}

func TestCIImageLatestIsMovedOnlyUnderTheLock(t *testing.T) {
	if msg := checkCIImageLatest(readCIYAML(t)); msg != "" {
		t.Fatal(msg)
	}
}

func TestCIImageLatestCheckCatchesDrift(t *testing.T) {
	ci := readCIYAML(t)
	edit := func(old, new string) string {
		t.Helper()
		if !strings.Contains(ci, old) {
			t.Fatalf("ci.yml no longer contains %q; update this test", old)
		}
		return strings.Replace(ci, old, new, 1)
	}
	cases := []struct{ name, ci, want string }{
		{"current", ci, ""},
		// The first version of PR #144.
		{"latest decided in the build job", edit("            type=sha,", "            type=raw,value=latest\n            type=sha,"), "outside the locked promote step"},
		{"semver tag writes latest", edit("          flavor: |\n            latest=false\n", ""), "latest=false"},
		{"no lock", edit("    concurrency:\n      group: ghcr-pilot-cli-latest\n      cancel-in-progress: false\n      queue: max\n", ""), "without a concurrency lock"},
		{"lock cancels the running promotion", edit("      cancel-in-progress: false\n", "      cancel-in-progress: true\n"), "without a concurrency lock"},
		{"lock per run", edit("      group: ghcr-pilot-cli-latest\n", "      group: ghcr-pilot-cli-latest-${{ github.run_id }}\n"), "not one lock shared"},
		{"lock per commit", edit("      group: ghcr-pilot-cli-latest\n", "      group: ghcr-pilot-cli-latest-${{ github.sha }}\n"), "not one lock shared"},
		{"queued promote can be cancelled", edit("      queue: max\n", ""), "queue must be max"},
		{"main read before the lock", edit(`head=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)`, `head=$MAIN_AT_BUILD`), "must read main's head"},
		{"promotion on any ref", edit("    if: github.repository == 'kjelly/pilot' && github.ref == 'refs/heads/main'\n", ""), "want only main of kjelly/pilot"},
		{"promotion in forks", edit("    if: github.repository == 'kjelly/pilot' && github.ref == 'refs/heads/main'\n", "    if: github.ref == 'refs/heads/main'\n"), "want only main of kjelly/pilot"},
		{"promotion without the image job", edit("    needs: image\n", "    needs: test\n"), "want the image job"},
		{"promotion dropped", edit(`--tag "$IMAGE:latest"`, `--tag "$IMAGE:edge"`), "want exactly 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIImageLatest(tc.ci)
			if tc.want == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, got)
			}
		})
	}
}

// TestCIImageLatestNeverGoesBack runs ci.yml's promote script against fake
// gh and docker. Runs A and B are both on main; B is merged after A. The
// lock makes each promotion atomic, so every order of "merge B", "promote A"
// and "promote B" (B's CI starts only after its merge) is a serial order.
// The order from the review (A promotes after B) must leave :latest on B.
func TestCIImageLatestNeverGoesBack(t *testing.T) {
	var wf ciImageWorkflow
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	writers, script := latestWriters(wf)
	if len(writers) != 1 {
		t.Fatalf("steps that move :latest: %v, want exactly 1", writers)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	stubs := map[string]string{
		"gh": `#!/bin/sh
[ "$*" = "api repos/kjelly/pilot/git/ref/heads/main --jq .object.sha" ] || { echo "unexpected: gh $*" >&2; exit 1; }
cat "$STATE/main"
`,
		"docker": `#!/bin/sh
[ "$1 $2 $3 $4 $5" = "buildx imagetools create --tag $IMAGE:latest" ] || { echo "unexpected: docker $*" >&2; exit 1; }
printf %s "${6#"$IMAGE@"}" > "$STATE/latest"
`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	const (
		shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	// rank orders the images by commit age.
	rank := map[string]int{"sha256:old": 0, "sha256:a": 1, "sha256:b": 2}
	digest := map[string]string{shaA: "sha256:a", shaB: "sha256:b"}

	orders := [][]string{
		{"merge B", "promote A", "promote B"},
		{"merge B", "promote B", "promote A"}, // the review's order
		{"promote A", "merge B", "promote B"},
	}
	for _, order := range orders {
		t.Run(strings.Join(order, ", "), func(t *testing.T) {
			state := t.TempDir()
			write := func(name, v string) {
				if err := os.WriteFile(filepath.Join(state, name), []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			latest := func() string {
				b, err := os.ReadFile(filepath.Join(state, "latest"))
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			write("main", shaA)
			write("latest", "sha256:old")
			for _, ev := range order {
				before := latest()
				switch ev {
				case "merge B":
					write("main", shaB)
				default:
					sha := shaA
					if ev == "promote B" {
						sha = shaB
					}
					// GitHub runs `shell: bash` as bash --noprofile --norc -eo pipefail.
					cmd := exec.Command(bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
					cmd.Env = append(os.Environ(),
						"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
						"STATE="+state,
						"IMAGE=ghcr.io/kjelly/pilot-cli",
						"GITHUB_REPOSITORY=kjelly/pilot",
						"GITHUB_SHA="+sha,
						"DIGEST="+digest[sha],
					)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("%s: %v\n%s", ev, err, out)
					}
				}
				if after := latest(); rank[after] < rank[before] {
					t.Fatalf("%s moved :latest back from %s to %s", ev, before, after)
				}
			}
			if got := latest(); got != "sha256:b" {
				t.Fatalf(":latest is %s, want sha256:b (main's head)", got)
			}
		})
	}
}

var dockerfileARGRE = regexp.MustCompile(`(?m)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)`)

// checkCIImageBuildArgs reports why the build-args CI passes for
// images/Dockerfile.pilot-cli differ from the Dockerfile's ARGs, or "".
func checkCIImageBuildArgs(ciYAML, dockerfile string) string {
	var wf ciImageWorkflow
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return "parse ci.yml: " + err.Error()
	}
	var buildArgs map[string]string
	for name, job := range wf.Jobs {
		for _, st := range job.Steps {
			if !strings.HasPrefix(st.Uses, "docker/build-push-action@") || st.With["file"] != "images/Dockerfile.pilot-cli" {
				continue
			}
			if buildArgs != nil {
				return "more than one step builds images/Dockerfile.pilot-cli (job " + name + ")"
			}
			buildArgs = map[string]string{}
			for line := range strings.SplitSeq(fmt.Sprint(st.With["build-args"]), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
					buildArgs[k] = v
				}
			}
		}
	}
	if buildArgs == nil {
		return "no build-push-action step builds images/Dockerfile.pilot-cli"
	}
	args := map[string]bool{}
	for _, m := range dockerfileARGRE.FindAllStringSubmatch(dockerfile, -1) {
		args[m[1]] = true
	}
	for _, a := range slices.Sorted(maps.Keys(args)) {
		if _, ok := buildArgs[a]; !ok {
			return "Dockerfile ARG " + a + " is not passed as a build-arg in ci.yml"
		}
	}
	for _, k := range slices.Sorted(maps.Keys(buildArgs)) {
		if !args[k] {
			return "ci.yml passes build-arg " + k + ", which images/Dockerfile.pilot-cli has no ARG for"
		}
		if strings.HasSuffix(k, "_VERSION") && buildArgs[k] != "${{ steps.version.outputs.value }}" {
			return "build-arg " + k + " is " + strconv.Quote(buildArgs[k]) + ", want the release tag version (${{ steps.version.outputs.value }})"
		}
	}
	return ""
}

func readPilotCLIDockerfile(t *testing.T) string {
	t.Helper()
	df, err := os.ReadFile(filepath.Join(repoRootForTest(t), "images", "Dockerfile.pilot-cli"))
	if err != nil {
		t.Fatal(err)
	}
	return string(df)
}

func TestCIImageBuildArgsMatchDockerfileARGs(t *testing.T) {
	if msg := checkCIImageBuildArgs(readCIYAML(t), readPilotCLIDockerfile(t)); msg != "" {
		t.Fatal(msg)
	}
}

func TestCIImageBuildArgsCheckCatchesDrift(t *testing.T) {
	ci, df := readCIYAML(t), readPilotCLIDockerfile(t)
	const loginProbe = "            LOGIN_PROBE_VERSION=${{ steps.version.outputs.value }}\n"
	if !strings.Contains(ci, loginProbe) {
		t.Fatalf("ci.yml no longer contains %q; update this test", loginProbe)
	}
	cases := []struct{ name, ci, df, want string }{
		{"current", ci, df, ""},
		{"ARG not passed", strings.Replace(ci, loginProbe, "", 1), df, "LOGIN_PROBE_VERSION is not passed"},
		{"new ARG", ci, strings.Replace(df, "ARG PILOT_GIT_SHA=unknown\n", "ARG PILOT_GIT_SHA=unknown\nARG NEW_TOOL_VERSION=0.0.0-dev\n", 1), "NEW_TOOL_VERSION is not passed"},
		{"renamed ARG", ci, strings.ReplaceAll(df, "LOGIN_PROBE_VERSION", "PILOT_LOGIN_PROBE_VERSION"), "PILOT_LOGIN_PROBE_VERSION is not passed"},
		{"build-arg without an ARG", strings.Replace(ci, loginProbe, loginProbe+"            OLD_TOOL_VERSION=${{ steps.version.outputs.value }}\n", 1), df, "OLD_TOOL_VERSION, which images/Dockerfile.pilot-cli has no ARG for"},
		{"version not from the tag", strings.Replace(ci, loginProbe, "            LOGIN_PROBE_VERSION=0.0.0-dev\n", 1), df, "want the release tag version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIImageBuildArgs(tc.ci, tc.df)
			if tc.want == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, got)
			}
		})
	}
}

// checkCIImageTagTrigger reports a push tag filter that also matches tags
// that are not v<digit>...: metadata-action makes no image tag for a tag
// that is not semver (only a warning), and build-push-action then fails with
// "tag is needed when pushing to registry" after the whole CI has run.
func checkCIImageTagTrigger(ciYAML string) string {
	var wf struct {
		On struct {
			Push struct{ Tags []string }
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return "parse ci.yml: " + err.Error()
	}
	if len(wf.On.Push.Tags) == 0 {
		return "ci.yml runs on no tag pushes, so no release image is published"
	}
	for _, p := range wf.On.Push.Tags {
		if !strings.HasPrefix(p, "v[0-9]") {
			return "push tag filter " + strconv.Quote(p) + " also matches tags that are not releases (want v[0-9]...)"
		}
	}
	return ""
}

func TestCIImageReleaseTagTriggerMatchesReleasesOnly(t *testing.T) {
	if msg := checkCIImageTagTrigger(readCIYAML(t)); msg != "" {
		t.Fatal(msg)
	}
}

func TestCIImageReleaseTagTriggerCheckCatchesDrift(t *testing.T) {
	cases := []struct{ name, ci, want string }{
		{"release tags", "on:\n  push:\n    branches: [main]\n    tags: ['v[0-9]*']\n", ""},
		{"any v tag", "on:\n  push:\n    branches: [main]\n    tags: ['v*']\n", "also matches tags that are not releases"},
		{"no tag trigger", "on:\n  push:\n    branches: [main]\n", "no tag pushes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIImageTagTrigger(tc.ci)
			if tc.want == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, got)
			}
		})
	}
}
