package cmd

import "testing"

func TestCheckProbeFlag(t *testing.T) {
	cases := []struct {
		changed bool
		probe   string
		wantErr bool
	}{
		{changed: false, probe: "", wantErr: false},
		{changed: true, probe: "", wantErr: true},
		{changed: true, probe: "   ", wantErr: true},
		{changed: true, probe: "true", wantErr: false},
	}
	for _, c := range cases {
		if err := checkProbeFlag(c.changed, c.probe); (err != nil) != c.wantErr {
			t.Errorf("checkProbeFlag(%v, %q) = %v, want error %v", c.changed, c.probe, err, c.wantErr)
		}
	}
}
