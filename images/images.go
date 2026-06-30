// Package images embeds the pre-baked pilot-target Dockerfiles into the
// binary so `pilot docker-target up --image-pilot <variant>` can build a
// missing image on demand — no separate `./images/build.sh` step and no
// dependency on the current working directory or repo layout.
//
// The Dockerfiles have no COPY/ADD, so callers can build them from an
// empty context (the bytes returned here are the whole story).
package images

import (
	"embed"
	"sort"
)

//go:embed Dockerfile.pilot-target-ubuntu
var dockerfiles embed.FS

// variantFiles maps a `--image-pilot` variant (the suffix after
// "pilot-target:") to its embedded Dockerfile.
var variantFiles = map[string]string{
	"ubuntu-24.04": "Dockerfile.pilot-target-ubuntu",
}

// DockerfileFor returns the embedded Dockerfile bytes for a pilot-target
// image variant (e.g. "ubuntu-24.04") and whether the variant is known.
func DockerfileFor(variant string) ([]byte, bool) {
	name, ok := variantFiles[variant]
	if !ok {
		return nil, false
	}
	data, err := dockerfiles.ReadFile(name)
	if err != nil {
		// Shouldn't happen: the file is embedded at build time.
		return nil, false
	}
	return data, true
}

// Variants lists the known pilot-target image variants, sorted, for
// error messages ("known: ubuntu-24.04").
func Variants() []string {
	out := make([]string, 0, len(variantFiles))
	for v := range variantFiles {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
