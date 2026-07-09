package docs

import "testing"

func TestVersionHashStable(t *testing.T) {
	a := VersionHash("2.14.5", []string{"lineinfile", "copy", "apt"})
	b := VersionHash("2.14.5", []string{"apt", "copy", "lineinfile"}) // different order
	if a != b {
		t.Errorf("hash should be order-independent: %s != %s", a, b)
	}
	c := VersionHash("2.15.0", []string{"lineinfile", "copy", "apt"})
	if a == c {
		t.Error("hash should differ for different version")
	}
}
