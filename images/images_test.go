package images

import (
	"strings"
	"testing"
)

// TestDockerfileFor_KnownVariant guards that the embedded Dockerfile is
// present AND is the systemd-enabled one (so `--image-pilot ubuntu-24.04
// --systemd` can boot /sbin/init). If someone drops systemd-sysv from
// the Dockerfile, this trips.
func TestDockerfileFor_KnownVariant(t *testing.T) {
	df, ok := DockerfileFor("ubuntu-24.04")
	if !ok {
		t.Fatal("ubuntu-24.04 should be a known variant")
	}
	for _, want := range []string{"FROM ubuntu:24.04", "systemd-sysv", "python3"} {
		if !strings.Contains(string(df), want) {
			t.Errorf("embedded Dockerfile missing %q", want)
		}
	}
}

// TestDockerfileFor_UnknownVariant returns !ok so the CLI can surface a
// helpful "known variants" error instead of trying to build nothing.
func TestDockerfileFor_UnknownVariant(t *testing.T) {
	if _, ok := DockerfileFor("fedora-99"); ok {
		t.Error("fedora-99 should be unknown")
	}
}

// TestVariants_Sorted keeps the error-message ordering deterministic.
func TestVariants_Sorted(t *testing.T) {
	v := Variants()
	if len(v) == 0 {
		t.Fatal("expected at least one variant")
	}
	for i := 1; i < len(v); i++ {
		if v[i-1] > v[i] {
			t.Errorf("Variants not sorted: %v", v)
		}
	}
}
