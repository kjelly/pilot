package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Spec Q8 (the default taken before the maintainer's confirmation) from the
// command: an empty string for login_shell, display_name or email is "no value"
// in the preview too, the one Build that the writer uses, so what the preview
// shows is what an apply converges to. Against a user that has none of the three
// there is nothing to do; against one that has them the preview shows them
// cleared. first, last and home_directory are refused before anything is read.

// userFindWithout is the captured user_find --all with the reader given admins
// (as the fake does by default) and the named attributes taken off one user.
func userFindWithout(f *fakeIPA, user string, attrs ...string) string {
	var env map[string]any
	if err := json.Unmarshal(f.withAdmins(f.fixture("user-find-states")), &env); err != nil {
		f.t.Fatal(err)
	}
	for _, e := range env["result"].(map[string]any)["result"].([]any) {
		u := e.(map[string]any)
		if u["uid"].([]any)[0] == user {
			for _, a := range attrs {
				delete(u, a)
			}
		}
	}
	out, _ := json.Marshal(env)
	return string(out)
}

// captureRosterWith is captureRoster with p1-nokeys's own line replaced.
func captureRosterWith(line string) string {
	var out []string
	for _, l := range strings.Split(strings.Replace(captureRoster, "%s", "/bin/sh", 1), "\n") {
		if strings.HasPrefix(l, "  - {name: p1-nokeys,") {
			l = "  - {name: p1-nokeys, " + line + "}"
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func TestReconcileGolangPreviewReadsAnEmptyStringAsNoValue(t *testing.T) {
	roster := captureRosterWith(`first: P1, last: NoKeys, display_name: "", email: "", login_shell: ""`)
	t.Run("a user that has none of the three: nothing to do", func(t *testing.T) {
		f := newFakeIPA(t, "p1-self")
		withFakeDialer(t, f)
		f.answers = map[string]string{"user_find": userFindWithout(f, "p1-nokeys", "displayname", "mail", "loginshell")}
		golangWorkspace(t, roster, nil)
		out, err := runGolangPreview(t)
		if err != nil || !strings.Contains(out, "沒有任何寫入") {
			t.Fatalf("preview: %v\n%s", err, out)
		}
	})
	t.Run("a user that has them: the preview shows them cleared", func(t *testing.T) {
		f := newFakeIPA(t, "p1-self")
		withFakeDialer(t, f)
		dir := golangWorkspace(t, roster, nil)
		plan := dir + "/plan.json"
		out, err := runGolangPreview(t, "--plan-out", plan)
		if err != nil || !strings.Contains(out, "計畫：1 個寫入") || !strings.Contains(out, "user.update") {
			t.Fatalf("preview: %v\n%s", err, out)
		}
		data, err := os.ReadFile(plan)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Operations []struct {
				Kind, Object string
				Fields       map[string]struct{ From, To any }
			}
		}
		if err := json.Unmarshal(data, &doc); err != nil || len(doc.Operations) != 1 {
			t.Fatalf("plan = %s (%v)", data, err)
		}
		op := doc.Operations[0]
		if op.Kind != "user.update" || op.Object != "p1-nokeys" {
			t.Fatalf("operation = %+v", op)
		}
		for _, k := range []string{"displayname", "loginshell"} {
			if c, ok := op.Fields[k]; !ok || c.To != "" || c.From == "" {
				t.Fatalf("%s = %+v, want a value cleared", k, c)
			}
		}
		if c, ok := op.Fields["mail"]; !ok || c.From == nil {
			t.Fatalf("mail = %+v, want the live mail cleared", c)
		} else if to, _ := c.To.([]any); len(to) != 0 {
			t.Fatalf("mail to = %v, want an empty list", c.To)
		}
	})
}

// An empty first, last or home_directory is refused before the tunnel is built:
// the server refuses them (captured), and the engine finds that out at the door.
func TestReconcileGolangPreviewRefusesAnEmptyFirstLastOrHome(t *testing.T) {
	for _, key := range []string{"first", "last", "home_directory"} {
		t.Run(key, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			targets := withFakeDialer(t, f)
			fields := map[string]string{"first": "P1", "last": "NoKeys"}
			fields[key] = `""`
			var parts []string
			for _, k := range []string{"first", "last", "home_directory"} {
				if v, ok := fields[k]; ok {
					parts = append(parts, k+": "+v)
				}
			}
			golangWorkspace(t, captureRosterWith(strings.Join(parts, ", ")), nil)
			out, err := runGolangPreview(t)
			if err == nil || !strings.Contains(err.Error(), key+" must not be empty") || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d)\n%s", err, processExitCode(err), out)
			}
			if len(*targets) != 0 {
				t.Fatalf("built a tunnel to %+v", *targets)
			}
			assertNoLogin(t, f)
		})
	}
}
