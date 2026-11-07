package livehooks

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The released pilot has none of the injection points in it: the names the driver sets
// are not in a binary built without the tag, and are in one built with it (the control:
// without it the scan could never fail). Spec D31: "預設與發佈的 binary 不含這些檔案".
func TestTheReleasedBinaryHasNoInjectionPoints(t *testing.T) {
	if testing.Short() {
		t.Skip("builds pilot twice")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := func(tags string) []byte {
		out := filepath.Join(t.TempDir(), "pilot")
		args := []string{"build", "-o", out}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		cmd := exec.Command("go", append(args, "./cmd/pilot")...)
		cmd.Dir = root
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %v: %v\n%s", args, err, msg)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, name := range []string{EnvDir, EnvPoints} {
		if bytes.Contains(build(""), []byte(name)) {
			t.Errorf("the default build holds %q: the injection points are in the released binary", name)
		}
	}
	tagged := build("identity_live_hooks")
	for _, name := range []string{EnvDir, EnvPoints} {
		if !bytes.Contains(tagged, []byte(name)) {
			t.Errorf("the tagged build does not hold %q: the scan above cannot fail", name)
		}
	}
}
