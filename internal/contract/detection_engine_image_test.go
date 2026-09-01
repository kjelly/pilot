package contract

import (
	"os"
	"strings"
	"testing"
)

// TestDetectionEngineImage_PackagesRuntimeArtifact locks the control image's
// supply-chain boundary: the pilot-cli image must build the static runtime
// binary and ship its checksum sidecar, plus the feature-profile tree that
// detection-engine-apply.yml copies to the managed host.
func TestDetectionEngineImage_PackagesRuntimeArtifact(t *testing.T) {
	root := contractRepoRoot(t)
	raw, err := os.ReadFile(root + "/images/Dockerfile.pilot-cli")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(raw)

	for _, want := range []string{
		"ARG DETECTION_ENGINE_VERSION=0.0.0-dev",
		"CGO_ENABLED=0 GOOS=linux GOARCH=amd64",
		"./cmd/pilot-detection-engine",
		"sha256sum pilot-detection-engine-linux-amd64",
		"COPY --from=builder /out/pilot-detection-engine-linux-amd64 /pilot/dist/pilot-detection-engine-linux-amd64",
		"COPY --from=builder /out/pilot-detection-engine-linux-amd64.sha256 /pilot/dist/pilot-detection-engine-linux-amd64.sha256",
		"COPY monitoring/ monitoring/",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile.pilot-cli must contain %q", want)
		}
	}
}
