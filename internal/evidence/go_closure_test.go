package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func supportedBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{GoVersion: "go1.26.8", Path: pilotMain, Main: debug.Module{Path: pilotModule}, Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"}, {Key: "GOAMD64", Value: "v1"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "-compiler", Value: "gc"}, {Key: "-buildmode", Value: "exe"}}}
}
func TestGoBuildContextRefusesUnmodeledInputs(t *testing.T) {
	good := supportedBuildInfo()
	build, err := validateBuildInfo(good)
	if err != nil {
		t.Fatal(err)
	}
	if build.GOAMD64 != "v1" || len(build.SettingsSHA256) != 64 || len(build.ModulesSHA256) != 64 {
		t.Fatal("actual build fingerprints missing")
	}
	for _, setting := range []debug.BuildSetting{{Key: "-tags", Value: "custom"}, {Key: "-gcflags", Value: "all=-N"}, {Key: "-asmflags", Value: "all=-D custom"}, {Key: "-ldflags", Value: "-X main.value=custom"}, {Key: "GOEXPERIMENT", Value: "custom"}, {Key: "-race", Value: "true"}, {Key: "GOAMD64", Value: "v3"}, {Key: "CGO_ENABLED", Value: "1"}} {
		t.Run(setting.Key, func(t *testing.T) {
			info := supportedBuildInfo()
			info.Settings = append(info.Settings, setting)
			if _, err := validateBuildInfo(info); err == nil {
				t.Fatal("unmodeled binary context accepted")
			}
		})
	}
	for _, mutate := range []func(*debug.BuildInfo){func(i *debug.BuildInfo) { i.Path = "other/main" }, func(i *debug.BuildInfo) { i.Main.Path = "other/module" }, func(i *debug.BuildInfo) { i.GoVersion = "go1.26.7" }, func(i *debug.BuildInfo) { i.Main.Replace = &debug.Module{Path: "../other"} }, func(i *debug.BuildInfo) { i.Deps = []*debug.Module{{Path: "example.com/local", Version: "v1.0.0"}} }} {
		info := supportedBuildInfo()
		mutate(info)
		if _, err := validateBuildInfo(info); err == nil {
			t.Fatal("mismatched/local binary identity accepted")
		}
	}
}
func TestGoSourceListingIsAtomicAndTracksEmbedMembership(t *testing.T) {
	root := t.TempDir()
	writeClosureFile(t, root, "cmd/pilot/main.go", "package main\n")
	writeClosureFile(t, root, "cmd/pilot/assets/a.txt", "embedded\n")
	p := listedPackage{ImportPath: pilotMain, Dir: filepath.Join(root, "cmd/pilot"), Module: &listedModule{Path: pilotModule}, GoFiles: []string{"main.go"}, EmbedFiles: []string{"assets/a.txt"}, EmbedPatterns: []string{"assets/*.txt"}}
	raw, _ := json.Marshal(p)
	files, patterns, _, err := parseGoSourceListing(root, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatal("selected Go/embed files missing")
	}
	for _, want := range []string{"cmd/pilot/*.go", "cmd/pilot/*.s", "cmd/pilot/*.syso", "cmd/pilot/**"} {
		found := false
		for _, got := range patterns {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("new Go/embed member has no scope: %s", want)
		}
	}
	for _, broken := range [][]byte{append(append([]byte(nil), raw...), []byte("\n{broken")...), []byte(`{"ImportPath":"other"}`), []byte(`{"Incomplete":true}`), []byte(`{"Error":{"Err":"error"}}`), []byte(`{"DepsErrors":[{}]}`)} {
		files, _, _, err := parseGoSourceListing(root, bytes.NewReader(broken))
		if err == nil || len(files) != 0 {
			t.Fatal("partial/error Go listing yielded an accepted partial closure")
		}
	}
	p.Module.Replace = &listedModule{Path: "../outside"}
	raw, _ = json.Marshal(p)
	if _, _, _, err := parseGoSourceListing(root, bytes.NewReader(raw)); err == nil {
		t.Fatal("local replacement accepted")
	}
	p.Module.Replace = nil
	p.Dir = "/unproved/outside"
	raw, _ = json.Marshal(p)
	if _, _, _, err := parseGoSourceListing(root, bytes.NewReader(raw)); err == nil {
		t.Fatal("source outside candidate/cache accepted")
	}
}
func TestSanitizeBoundExecutionIdentitiesOnly(t *testing.T) {
	root := t.TempDir()
	path := "internal/detection/prompts/host-anomaly-v1.txt"
	writeClosureFile(t, root, path, "public embedded bytes\n")
	entry, err := rawClosureFile(root, filepath.Join(root, path), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "escaping", "fingerprint", "mode"} {
		t.Run(bad, func(t *testing.T) {
			file := *entry
			if bad == "escaping" {
				file.Path = "../" + path
			}
			if bad == "fingerprint" {
				file.SHA256 = strings.Repeat("0", 64)
			}
			if bad == "mode" {
				file.Mode = "100755"
			}
			rec := &Record{Schema: Schema, Closure: &Closure{Files: []File{file}, Patterns: []string{"internal/detection/*-v1.txt"}}, Operator: path, Tooling: map[string]string{path: path}}
			if err := SanitizeRecord(rec, []SecretSource{{Key: "api_token", value: "v1"}}, root); err != nil {
				t.Fatal(err)
			}
			if bad == "" {
				if rec.Closure.Files[0].Path != path || rec.Closure.Patterns[0] != "internal/detection/*-v1.txt" {
					t.Fatal("bound Git execution identity corrupted")
				}
			} else if strings.Contains(rec.Closure.Files[0].Path, "v1") {
				t.Fatal("malformed/unbound execution path exempted arbitrary secret")
			}
			if strings.Contains(rec.Operator, "v1") {
				t.Fatal("operator path inherited execution identity exemption")
			}
			for key, value := range rec.Tooling {
				if strings.Contains(key, "v1") || strings.Contains(value, "v1") {
					t.Fatal("dynamic map path inherited execution identity exemption")
				}
			}
		})
	}
	_ = os.Remove(filepath.Join(root, path))
}
