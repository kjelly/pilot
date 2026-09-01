package detection

import "testing"

func TestSubjectKey_IsManagedHost(t *testing.T) {
	managed := SubjectKey{ID: "host01", Kind: SubjectKindManagedHost, Site: "hq"}
	if !managed.IsManagedHost() {
		t.Fatalf("%+v should be a managed host", managed)
	}

	external := SubjectKey{ID: "core-sw-01", Kind: "network_device", Site: "hq"}
	if external.IsManagedHost() {
		t.Fatalf("%+v must not be classified as managed host", external)
	}
}

func TestSubjectKey_IsValid(t *testing.T) {
	cases := []struct {
		name string
		key  SubjectKey
		want bool
	}{
		{"complete", SubjectKey{ID: "core-sw-01", Kind: "network_device", Site: "hq"}, true},
		{"zero value", SubjectKey{}, false},
		{"missing id", SubjectKey{Kind: "network_device", Site: "hq"}, false},
		{"missing kind", SubjectKey{ID: "core-sw-01", Site: "hq"}, false},
		{"missing site is not by itself invalid", SubjectKey{ID: "core-sw-01", Kind: "network_device"}, true},
	}
	for _, c := range cases {
		if got := c.key.IsValid(); got != c.want {
			t.Errorf("%s: IsValid() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSubjectKey_StringNeverLeaksBeyondFields(t *testing.T) {
	key := SubjectKey{ID: "core-sw-01", Kind: "network_device", Site: "hq"}
	got := key.String()
	want := "network_device/core-sw-01@hq"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
