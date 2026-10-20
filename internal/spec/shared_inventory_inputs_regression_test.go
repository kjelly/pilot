package spec

import (
	"os/exec"
	"testing"
)

// The uploader and readers must derive their endpoint from the same resolved
// alias/port. Defaulting all three in one set_fact reads the old alias/port.
func TestRegression_ThanosSharedInventoryInputs(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name     string
		vars     map[string]any
		endpoint string
	}{
		{"defaults", nil, "thanos-s3-backend:8333"},
		{"inventory alias and port", map[string]any{"thanos_s3_alias": "archive.example.test", "thanos_s3_port": 9443}, "archive.example.test:9443"},
		{"external endpoint", map[string]any{"thanos_s3_alias": "unused", "thanos_s3_port": 9443, "thanos_s3_endpoint": "external.example.test:443"}, "external.example.test:443"},
	} {
		for _, id := range []string{"prometheus", "thanos-query"} {
			t.Run(tc.name+"/"+id, func(t *testing.T) {
				t.Parallel()
				play := loadFirstPlay(t, id+"-apply.yml")
				tasks := append(pickTasks(play, isDefaultsTask), showTask([]string{"thanos_s3_endpoint", "thanos_s3_bucket"}))
				got := runInventoryPlay(t, id, play["vars"], tasks, tc.vars)
				if got["thanos_s3_endpoint"] != tc.endpoint || got["thanos_s3_bucket"] != "pilot-thanos-metrics" {
					t.Fatalf("resolved inputs = %v, want endpoint %s and shared bucket", got, tc.endpoint)
				}
			})
		}
	}
}
