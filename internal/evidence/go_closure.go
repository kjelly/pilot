package evidence

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
)

const pilotModule = "github.com/kjelly/pilot"
const pilotMain = pilotModule + "/cmd/pilot"

type ControllerBuild struct {
	SourcesSHA256       string `json:"sources_sha256"`
	RebuiltBinarySHA256 string `json:"rebuilt_binary_sha256"`
	GoVersion           string `json:"go_version"`
	Path                string `json:"path"`
	Module              string `json:"module"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	GOAMD64             string `json:"goamd64"`
	CGO                 string `json:"cgo"`
	SettingsSHA256      string `json:"settings_sha256"`
	ModulesSHA256       string `json:"modules_sha256"`
	settings            map[string]string
	modules             []ControllerModule
}
type ControllerModule struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}
type listedModule struct {
	Path, Version, Sum, Dir string
	Replace                 *listedModule
}
type listedPackage struct {
	ImportPath, Dir                                                                                                                                    string
	Standard, Incomplete                                                                                                                               bool
	Error                                                                                                                                              *struct{ Err string }
	DepsErrors                                                                                                                                         []any
	Module                                                                                                                                             *listedModule
	GoFiles, CgoFiles, IgnoredGoFiles, SFiles, SysoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SwigFiles, SwigCXXFiles, EmbedFiles, EmbedPatterns []string
}

func validateBuildInfo(info *debug.BuildInfo) (*ControllerBuild, error) {
	if info == nil || info.GoVersion != "go1.26.8" || info.Path != pilotMain || info.Main.Path != pilotModule || info.Main.Replace != nil {
		return nil, fmt.Errorf("unsupported Go binary/module identity")
	}
	build := &ControllerBuild{GoVersion: info.GoVersion, Path: info.Path, Module: info.Main.Path, settings: map[string]string{}}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			if setting.Value != "linux" {
				return nil, fmt.Errorf("unsupported Go OS")
			}
		case "GOARCH":
			if setting.Value != "amd64" {
				return nil, fmt.Errorf("unsupported Go architecture")
			}
		case "GOAMD64":
			if setting.Value != "v1" {
				return nil, fmt.Errorf("unsupported Go architecture tuning")
			}
		case "CGO_ENABLED":
			if setting.Value != "0" {
				return nil, fmt.Errorf("unsupported cgo binary")
			}
		case "-compiler":
			if setting.Value != "gc" {
				return nil, fmt.Errorf("unsupported compiler")
			}
		case "-buildmode":
			if setting.Value != "exe" {
				return nil, fmt.Errorf("unsupported build mode")
			}
		case "-trimpath":
			if setting.Value != "true" {
				return nil, fmt.Errorf("unsupported trimpath setting")
			}
		case "vcs", "vcs.revision", "vcs.time", "vcs.modified", "DefaultGODEBUG":
		default:
			if setting.Value != "" {
				return nil, fmt.Errorf("unmodeled Go build setting")
			}
		}
		build.settings[setting.Key] = setting.Value
	}
	for key, value := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "-compiler": "gc", "-buildmode": "exe", "-trimpath": "true"} {
		if build.settings[key] != value {
			return nil, fmt.Errorf("missing fixed Go build setting")
		}
	}
	for _, module := range info.Deps {
		if module.Replace != nil || module.Sum == "" {
			return nil, fmt.Errorf("unproved replaced/local Go module")
		}
		build.modules = append(build.modules, ControllerModule{Path: module.Path, Version: module.Version, Sum: module.Sum})
	}
	sort.Slice(build.modules, func(i, j int) bool { return build.modules[i].Path < build.modules[j].Path })
	build.GOOS = build.settings["GOOS"]
	build.GOARCH = build.settings["GOARCH"]
	build.GOAMD64 = build.settings["GOAMD64"]
	build.CGO = build.settings["CGO_ENABLED"]
	settingsRaw, _ := json.Marshal(build.settings)
	modulesRaw, _ := json.Marshal(build.modules)
	build.SettingsSHA256 = digestBytes(settingsRaw)
	build.ModulesSHA256 = digestBytes(modulesRaw)
	return build, nil
}

// addGoSourceClosure uses the pinned OCI Go tool with exactly the supported
// build context. A partial/error listing or unverified cache never produces a
// partial accepted graph. Source files are hashed as binary inputs, not scanned
// as if Go/Jinja source literals were executed by Ansible.
func (c *Controller) addGoSourceClosure(r *resolver) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := buildinfo.ReadFile(c.binary)
	if err != nil {
		return err
	}
	build, err := validateBuildInfo(info)
	if err != nil {
		return err
	}
	for _, name := range []string{"go.mod", "go.sum", "go.work", "go.work.sum"} {
		r.patterns[name] = true
	}
	r.patterns["vendor/**"] = true
	for _, name := range []string{"go.work", "go.work.sum", "vendor"} {
		if _, err := os.Lstat(filepath.Join(c.root, name)); err == nil {
			return fmt.Errorf("unmodeled workspace/vendor build context")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	var listing, verification, diagnostics bytes.Buffer
	if err := c.execute("go-verify", nil, &verification, &diagnostics); err != nil {
		c.writeGoDiagnostics(&verification)
		c.writeGoDiagnostics(&diagnostics)
		return fmt.Errorf("go module cache verification failed")
	}
	if err := c.execute("go-list", nil, &listing, &diagnostics); err != nil {
		c.writeGoDiagnostics(&diagnostics)
		return fmt.Errorf("go dependency listing failed or incomplete")
	}
	files, patterns, modules, err := parseGoSourceListing(c.root, &listing)
	if err != nil {
		return err
	}
	for _, module := range build.modules {
		actual, ok := modules[module.Path]
		if !ok || actual != module {
			return fmt.Errorf("go module identity differs from tested binary")
		}
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		files = append(files, filepath.Join(c.root, name))
	}
	pending := map[string]*File{}
	for _, path := range files {
		entry, err := rawClosureFile(c.root, path, "compiled Go dependency")
		if err != nil {
			return err
		}
		pending[entry.Path] = entry
	}
	// Prove that the exact executable which orchestrates the chain was built
	// from these source bytes. Module/settings identity alone is insufficient.
	var identities []File
	for _, entry := range pending {
		identities = append(identities, *entry)
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Path < identities[j].Path })
	sort.Strings(patterns)
	bound, _ := json.Marshal(struct {
		Files             []File
		Patterns          []string
		Settings, Modules string
	}{identities, patterns, build.SettingsSHA256, build.ModulesSHA256})
	build.SourcesSHA256 = digestBytes(bound)
	previous := c.proof.Build
	if previous != nil && previous.SourcesSHA256 == build.SourcesSHA256 && previous.RebuiltBinarySHA256 == c.proof.BinarySHA256 {
		build.RebuiltBinarySHA256 = previous.RebuiltBinarySHA256
	} else {
		var rebuilt bytes.Buffer
		if err := c.execute("go-rebuild", nil, &rebuilt, &diagnostics); err != nil {
			c.writeGoDiagnostics(&diagnostics)
			return fmt.Errorf("pinned source rebuild failed")
		}
		build.RebuiltBinarySHA256 = strings.TrimSpace(rebuilt.String())
		if build.RebuiltBinarySHA256 != c.proof.BinarySHA256 {
			return fmt.Errorf("executed pilot binary differs from reproducible source rebuild")
		}
	}
	for name, entry := range pending {
		r.files[name] = entry
	}
	for _, pattern := range patterns {
		r.patterns[pattern] = true
	}
	c.proof.Build = build
	return nil
}

func parseGoSourceListing(root string, stream io.Reader) ([]string, []string, map[string]ControllerModule, error) {
	var files, patterns []string
	modules := map[string]ControllerModule{}
	decoder := json.NewDecoder(stream)
	count := 0
	mainSeen := false
	for {
		var p listedPackage
		err := decoder.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid partial Go package listing")
		}
		count++
		if p.Incomplete || p.Error != nil || len(p.DepsErrors) > 0 || len(p.CgoFiles) > 0 || len(p.CFiles) > 0 || len(p.CXXFiles) > 0 || len(p.MFiles) > 0 || len(p.FFiles) > 0 || len(p.SwigFiles) > 0 || len(p.SwigCXXFiles) > 0 {
			return nil, nil, nil, fmt.Errorf("unproved Go source/build context")
		}
		if p.Module != nil {
			if p.Module.Replace != nil {
				return nil, nil, nil, fmt.Errorf("replaced Go module is unsupported")
			}
			if p.Module.Path != pilotModule {
				if p.Module.Sum == "" {
					return nil, nil, nil, fmt.Errorf("go module lacks locked binary sum")
				}
				modules[p.Module.Path] = ControllerModule{Path: p.Module.Path, Version: p.Module.Version, Sum: p.Module.Sum}
			}
		}
		if p.Standard {
			continue
		}
		rel, err := filepath.Rel(root, p.Dir)
		inside := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
		if !inside {
			if p.Module == nil || !strings.HasPrefix(p.Dir, "/opt/pilot-modcache/") {
				return nil, nil, nil, fmt.Errorf("go source outside candidate/verified module cache")
			}
			continue
		}
		if p.Module == nil || p.Module.Path != pilotModule {
			return nil, nil, nil, fmt.Errorf("unexpected repository Go module")
		}
		if p.ImportPath == pilotMain {
			mainSeen = true
		}
		dir := filepath.ToSlash(rel)
		if dir == "." {
			dir = ""
		}
		for _, ext := range []string{"*.go", "*.s", "*.S", "*.syso", "*.c", "*.cc", "*.cpp", "*.h", "*.hh", "*.hpp", "*.m", "*.mm", "*.f", "*.F", "*.pgo"} {
			patterns = append(patterns, filepath.ToSlash(filepath.Join(dir, ext)))
		}
		if _, err := os.Stat(filepath.Join(p.Dir, "default.pgo")); err == nil {
			return nil, nil, nil, fmt.Errorf("unmodeled Go PGO build context")
		}
		selected := append(append(append(append(append([]string{}, p.GoFiles...), p.IgnoredGoFiles...), p.SFiles...), p.SysoFiles...), p.EmbedFiles...)
		for _, name := range selected {
			path := filepath.Join(p.Dir, name)
			relative, err := filepath.Rel(root, path)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return nil, nil, nil, fmt.Errorf("go input escapes candidate")
			}
			files = append(files, path)
		}
		if len(p.EmbedPatterns) > 0 {
			// A conservative subtree scope includes every possible new embed match,
			// including patterns whose former match set was empty.
			patterns = append(patterns, filepath.ToSlash(filepath.Join(dir, "**")))
			err := filepath.WalkDir(p.Dir, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}
	if count == 0 || !mainSeen {
		return nil, nil, nil, fmt.Errorf("go listing omitted the actual pilot main package")
	}
	return files, patterns, modules, nil
}
func rawClosureFile(root, path, via string) (*File, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("raw execution input escapes candidate")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("raw execution input is not a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	mode := "100644"
	if st.Mode()&0111 != 0 {
		mode = "100755"
	}
	return &File{Path: filepath.ToSlash(rel), Mode: mode, Blob: GitBlobOID(raw), SHA256: digestBytes(raw), Size: int64(len(raw)), Via: via}, nil
}

// Raw native diagnostics belong in the operator's run log, not the machine
// closure where they could contain untrusted source payloads.
func (c *Controller) writeGoDiagnostics(diagnostics *bytes.Buffer) {
	if c.diagnostics != nil {
		_, _ = c.diagnostics.Write(diagnostics.Bytes())
	}
}
