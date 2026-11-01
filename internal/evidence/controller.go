package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

const ControllerSchema = "pilot-controller/v3"
const ControllerProfile = "images/evidence-controller"

var controllerProfileFiles = []string{"Dockerfile", "profile.lock.json", "ansible.cfg", "launch.py", "probe.py"}

// ControllerProof is populated by real OCI execution, never a CLI attestation.
// NativeProbe contains effective Python/Ansible origins and discovery settings.
type ControllerProof struct {
	Build                   *ControllerBuild       `json:"build,omitempty"`
	Profile                 ControllerProfileProof `json:"profile"`
	Schema                  string                 `json:"schema"`
	ImageID                 string                 `json:"image_id"`
	ConfigSHA256            string                 `json:"config_sha256"`
	InventorySHA256         string                 `json:"inventory_sha256"`
	RenderedInventorySHA256 string                 `json:"rendered_inventory_sha256"`
	InventoryKind           string                 `json:"inventory_kind"`
	BinarySHA256            string                 `json:"binary_sha256"`
	PreProbeSHA256          string                 `json:"pre_probe_sha256"`
	PostProbeSHA256         string                 `json:"post_probe_sha256"`
	NativeProbe             *ControllerNativeProbe `json:"native_probe"`
	Steps                   ControllerStages       `json:"steps"`
}

type ControllerProfileProof struct {
	RecipeSHA256 string `json:"recipe_sha256"`
	LockSHA256   string `json:"lock_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	LaunchSHA256 string `json:"launch_sha256"`
	ProbeSHA256  string `json:"probe_sha256"`
}

type ControllerStages struct {
	Syntax      int `json:"L1 syntax check"`
	Check       int `json:"L3 check-mode dry-run"`
	Apply       int `json:"L4 apply"`
	Verify      int `json:"L5 verify"`
	Idempotency int `json:"L6 idempotency"`
}
type ControllerLoader struct {
	Config []string `json:"config"`
	Paths  []string `json:"paths"`
}
type ControllerCallback struct {
	Version        string `json:"version"`
	Origin         string `json:"origin"`
	SHA256         string `json:"sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Execution      string `json:"execution"`
}

type ControllerNativeProbe struct {
	Callback               ControllerCallback          `json:"callback"`
	UID                    int                         `json:"uid"`
	GID                    int                         `json:"gid"`
	User                   string                      `json:"user"`
	Group                  string                      `json:"group"`
	SSHIdentity            string                      `json:"ssh_identity"`
	Go                     string                      `json:"go"`
	Schema                 string                      `json:"schema"`
	Ansible                string                      `json:"ansible"`
	Python                 string                      `json:"python"`
	AnsibleOrigin          string                      `json:"ansible_origin"`
	PythonExecutable       string                      `json:"python_executable"`
	ConfigFile             string                      `json:"config_file"`
	ConfigSHA256           string                      `json:"config_sha256"`
	Collections            []string                    `json:"collections"`
	CollectionsScanSysPath bool                        `json:"collections_scan_sys_path"`
	Roles                  []string                    `json:"roles"`
	SysPath                []string                    `json:"sys_path"`
	Loaders                map[string]ControllerLoader `json:"loaders"`
}

type controllerPosixLock struct {
	Version        string `json:"version"`
	URL            string `json:"url"`
	SHA256         string `json:"sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	CallbackSHA256 string `json:"callback_sha256"`
}
type controllerLock struct {
	Posix                                       controllerPosixLock `json:"ansible_posix"`
	Schema, Base, Ansible, Python, Platform, Go string
	GoBase                                      string `json:"go_base"`
}

// Controller owns the immutable image ID and the private, natively checked
// context. Zero values cannot opt a closure into controlled resolution.
type Controller struct {
	mu                                                          sync.Mutex
	root, binary, image, inventory, originalInventory, stageDir string
	moduleCache                                                 string
	diagnostics                                                 io.Writer
	files                                                       map[string]string
	lock                                                        controllerLock
	probe                                                       []byte
	proof                                                       ControllerProof
	groups                                                      Inventory
	ready                                                       bool
	closed                                                      bool
	verifyDiagnostics                                           VerifyDiagnostics
}

func digestBytes(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// NewPinnedController builds only the committed profile recipe (no image flag),
// then resolves the immutable ID that all subsequent subprocesses actually run.
func NewPinnedController(root, binary string, log io.Writer) (*Controller, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	if !safeControllerMount(root) {
		return nil, fmt.Errorf("candidate path overlaps controller runtime")
	}
	if os.Getuid() != 1000 || os.Getgid() != 1000 {
		return nil, fmt.Errorf("pinned controller profile requires local UID/GID 1000")
	}
	c := &Controller{diagnostics: log, root: root, binary: binary, files: map[string]string{}, proof: ControllerProof{Schema: ControllerSchema, Steps: ControllerStages{}}}
	for _, name := range controllerProfileFiles {
		path := filepath.Join(root, ControllerProfile, name)
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("controller profile must contain regular file %s", name)
		}
		sum, err := SHA256File(path)
		if err != nil {
			return nil, err
		}
		c.files[path] = sum
	}
	raw, err := os.ReadFile(filepath.Join(root, ControllerProfile, "profile.lock.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &c.lock); err != nil {
		return nil, err
	}
	recipe, err := os.ReadFile(filepath.Join(root, ControllerProfile, "Dockerfile"))
	if err != nil {
		return nil, err
	}
	cache := os.Getenv("GOMODCACHE")
	if cache == "" {
		out, err := exec.Command("go", "env", "GOMODCACHE").Output()
		if err != nil {
			return nil, fmt.Errorf("locate readonly Go module cache: %w", err)
		}
		cache = strings.TrimSpace(string(out))
	}
	st, err := os.Stat(cache)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("pinned controller needs an existing readonly Go module cache")
	}
	c.moduleCache = cache
	if c.lock.Go != "go1.26.8" || !strings.Contains(c.lock.GoBase, "@sha256:") || !strings.HasPrefix(string(recipe), "FROM "+c.lock.GoBase+" AS go_toolchain\n") || c.lock.Schema != "pilot-controller-profile/v1" || !strings.Contains(c.lock.Base, "@sha256:") || c.lock.Platform != "linux/amd64" || !strings.Contains(string(recipe), "\nFROM "+c.lock.Base+"\n") {
		return nil, fmt.Errorf("controller recipe and pinned lock disagree")
	}
	if c.lock.Posix.Version != "2.1.0" || c.lock.Posix.SHA256 != "5ff232cf69492a991f2a0990dbb23ef25a600b7e9209de6e33377a6ff08a8a29" || c.lock.Posix.CallbackSHA256 != "cc2f6a845b1b7d8d87e16b7fed79b860e10ea9e9b372dd0bdcbd850b9654a032" || c.lock.Posix.ManifestSHA256 != "3899df5b1b390f51a7fc95ad8997c7e7030daf4f5265898f96977ef9ed8d4df5" || c.lock.Posix.URL != "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/ansible-posix-2.1.0.tar.gz" || !strings.Contains(string(recipe), "ADD --checksum=sha256:"+c.lock.Posix.SHA256+" "+c.lock.Posix.URL+" ") {
		return nil, fmt.Errorf("controller collection recipe and pinned lock disagree")
	}
	cmd := exec.Command("docker", "build", "--quiet", "--platform", c.lock.Platform, filepath.Join(root, ControllerProfile))
	cmd.Stderr = log
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("build pinned controller: %w", err)
	}
	inspect := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", strings.TrimSpace(string(out)))
	id, err := inspect.Output()
	if err != nil {
		return nil, fmt.Errorf("resolve controller image ID: %w", err)
	}
	c.image = strings.TrimSpace(string(id))
	if !validImageID(c.image) {
		return nil, fmt.Errorf("controller did not resolve to immutable image ID")
	}
	c.proof.ImageID = c.image
	c.proof.ConfigSHA256 = c.files[filepath.Join(root, ControllerProfile, "ansible.cfg")]
	c.proof.Profile = ControllerProfileProof{
		RecipeSHA256: c.files[filepath.Join(root, ControllerProfile, "Dockerfile")], LockSHA256: c.files[filepath.Join(root, ControllerProfile, "profile.lock.json")], ConfigSHA256: c.proof.ConfigSHA256, LaunchSHA256: c.files[filepath.Join(root, ControllerProfile, "launch.py")], ProbeSHA256: c.files[filepath.Join(root, ControllerProfile, "probe.py")],
	}
	sum, err := SHA256File(binary)
	if err != nil {
		return nil, err
	}
	c.files[binary] = sum
	c.proof.BinarySHA256 = sum
	if err := c.probeNative(); err != nil {
		return nil, err
	}
	return c, nil
}
func validImageID(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func (c *Controller) dockerArgs(tool string, args []string) []string {
	out := []string{"run", "--rm", "--read-only", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--network", "host", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--workdir", c.root, "--mount", "type=bind,src=" + c.root + ",dst=" + c.root + ",readonly", "--mount", "type=bind,src=" + c.binary + ",dst=/opt/pilot-bin/pilot,readonly"}
	out = append(out, "--mount", "type=bind,src="+c.moduleCache+",dst=/opt/pilot-modcache,readonly")
	for path := range c.files {
		if path == c.binary || strings.HasPrefix(path, c.root+string(filepath.Separator)) {
			continue
		}
		out = append(out, "--mount", "type=bind,src="+path+",dst="+path+",readonly")
	}
	return append(append(out, c.image, tool), args...)
}
func (c *Controller) execute(tool string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.Command("docker", c.dockerArgs(tool, args)...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Deliberately no host ANSIBLE_*/PYTHON*/HOME inheritance inside the container;
	// launch.py constructs the entire child environment in a fresh tmpfs.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("controlled %s failed: %w", tool, err)
	}
	return nil
}
func (c *Controller) probeNative() error {
	var out, errOut bytes.Buffer
	if err := c.execute("probe", nil, &out, &errOut); err != nil {
		return fmt.Errorf("native controller probe: %w: %s", err, errOut.String())
	}
	var probe ControllerNativeProbe
	if err := json.Unmarshal(out.Bytes(), &probe); err != nil {
		return fmt.Errorf("native controller probe is not JSON: %w", err)
	}
	if !validNativeProbe(&probe) || probe.Ansible != c.lock.Ansible || probe.Python != c.lock.Python || probe.ConfigSHA256 != c.proof.ConfigSHA256 {
		return fmt.Errorf("native controller origins/configuration differ from pinned profile")
	}

	var canonical bytes.Buffer
	if err := json.Compact(&canonical, out.Bytes()); err != nil {
		return err
	}
	if c.probe == nil {
		c.probe = append([]byte(nil), canonical.Bytes()...)
		c.proof.NativeProbe = &probe
		c.proof.PreProbeSHA256 = digestBytes(c.probe)
	} else if !bytes.Equal(c.probe, canonical.Bytes()) {
		return fmt.Errorf("native controller context changed during execution")
	}
	return nil
}

// PrepareInventory validates the actual rendered inventory and mounts only its
// explicit SSH keys into its private lifetime. Native inventory parsing supplies
// group ancestors too; manager-owned source paths are never mounted afterward.
func (c *Controller) PrepareInventory(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ready || c.stageDir != "" {
		return fmt.Errorf("controlled inventory is already prepared or controller closed")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	c.proof.RenderedInventorySHA256 = digestBytes(raw)
	stage, err := os.MkdirTemp("", "pilot-evidence-inventory-")
	if err != nil {
		return err
	}
	c.stageDir = stage
	stagedInputs := map[string]bool{}
	prepared := false
	defer func() {
		if !prepared {
			_ = os.RemoveAll(stage)
			for path := range stagedInputs {
				delete(c.files, path)
			}
			c.stageDir = ""
			c.inventory = ""
			c.originalInventory = ""
			c.groups = Inventory{}
			c.ready = false
			c.proof.InventorySHA256 = ""
			c.proof.RenderedInventorySHA256 = ""
			c.proof.InventoryKind = ""
		}
	}()
	keys := map[string]string{}
	supported := true
	var visit func(*yaml.Node) error
	visit = func(n *yaml.Node) error {
		if n.Kind == yaml.AliasNode {
			return fmt.Errorf("controlled inventory aliases unsupported")
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i], n.Content[i+1]
				if key.Value == "ansible_ssh_args" {
					if !regexp.MustCompile(`^-o ControlMaster=auto -o ControlPath="[^"\r\n]*" -o ControlPersist=60s$`).MatchString(val.Value) {
						supported = false
					}
					val.Value = "-o ControlMaster=no -o UserKnownHostsFile=/dev/null"
				}
				if key.Value == "ansible_ssh_private_key_file" {
					if val.Kind != yaml.ScalarNode || hasJinjaSyntax(val.Value) || !filepath.IsAbs(val.Value) {
						return fmt.Errorf("controlled inventory needs literal absolute SSH key paths")
					}
					if !safeControllerMount(val.Value) {
						return fmt.Errorf("SSH key mount overlaps controller runtime")
					}
					original := filepath.Clean(val.Value)
					staged, ok := keys[original]
					if !ok {
						key, err := readControllerKey(original)
						if err != nil {
							return err
						}
						staged = filepath.Join(stage, fmt.Sprintf("ssh-key-%03d", len(keys)))
						if err := os.WriteFile(staged, key, 0600); err != nil {
							return err
						}
						c.files[staged] = digestBytes(key)
						stagedInputs[staged] = true
						keys[original] = staged
					}
					// Only the snapshot is executed and bound after preparation;
					// manager cleanup may remove the source target's key safely.
					val.Value = staged
				}
			}
		}
		for _, ch := range n.Content {
			if err := visit(ch); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(&doc); err != nil {
		return err
	}
	raw, err = yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	c.originalInventory = path
	c.inventory = filepath.Join(c.stageDir, "inventory.yml")
	if err := os.WriteFile(c.inventory, raw, 0600); err != nil {
		return err
	}
	c.files[c.inventory] = digestBytes(raw)
	stagedInputs[c.inventory] = true
	c.proof.InventorySHA256 = digestBytes(raw)
	var out, errOut bytes.Buffer
	if err := c.execute("inventory", []string{"-i", c.inventory, "--list"}, &out, &errOut); err != nil {
		return fmt.Errorf("native inventory inspection failed: %w", err)
	}
	var native map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &native); err != nil {
		return err
	}
	inv := ParseInventoryYAML(string(raw))
	inv.Groups = map[string][]string{}
	type membership struct{ Hosts, Children []string }
	memberships := map[string]membership{}
	for group, value := range native {
		if group == "_meta" {
			continue
		}
		var m membership
		if err := json.Unmarshal(value, &m); err != nil {
			return err
		}
		memberships[group] = m
	}
	var hosts func(string, map[string]bool) []string
	hosts = func(group string, seen map[string]bool) []string {
		if seen[group] {
			return nil
		}
		seen[group] = true
		m := memberships[group]
		out := append([]string(nil), m.Hosts...)
		for _, child := range m.Children {
			out = append(out, hosts(child, seen)...)
		}
		return out
	}
	for group := range memberships {
		inv.Groups[group] = hosts(group, map[string]bool{})
	}
	var meta struct {
		Hostvars map[string]map[string]any `json:"hostvars"`
	}
	if err := json.Unmarshal(native["_meta"], &meta); err != nil {
		return err
	}
	if len(meta.Hostvars) == 0 {
		supported = false
	}
	for _, vars := range meta.Hostvars {
		for key, value := range vars {
			text, _ := value.(string)
			switch key {
			case "ansible_connection":
				if text != "ssh" {
					supported = false
				}
			case "ansible_host":
				if net.ParseIP(text) == nil {
					supported = false
				}
			case "ansible_user":
				if !safeInventoryName(text) {
					supported = false
				}
			case "ansible_port":
				port, ok := value.(float64)
				if !ok || port < 1 || port > 65535 || port != float64(int(port)) {
					supported = false
				}
			case "ansible_ssh_private_key_file":
				if _, ok := c.files[text]; !ok {
					supported = false
				}
			case "ansible_ssh_args":
				if text != "-o ControlMaster=no -o UserKnownHostsFile=/dev/null" {
					supported = false
				}
			case "ansible_ssh_common_args":
				if text != "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" {
					supported = false
				}
			case "ansible_ssh_pipelining":
				if value != true {
					supported = false
				}
			default:
				supported = false
			}
		}
		for _, key := range []string{"ansible_connection", "ansible_host", "ansible_user", "ansible_port", "ansible_ssh_private_key_file"} {
			if _, ok := vars[key]; !ok {
				supported = false
			}
		}
	}
	c.proof.InventoryKind = "unsupported"
	if supported {
		c.proof.InventoryKind = "pilot-rendered-ssh/v1"
	}
	c.groups = inv
	if err := c.checkInputs(); err != nil {
		return err
	}
	c.ready = true
	prepared = true
	return nil
}
func (c *Controller) checkInputs() error {
	for path, before := range c.files {
		after, err := SHA256File(path)
		if err != nil || after != before {
			return fmt.Errorf("controlled input changed during execution: %s", filepath.Base(path))
		}
	}
	return nil
}
func (c *Controller) Ready() bool          { return c != nil && c.ready && len(c.probe) > 0 }
func (c *Controller) Inventory() Inventory { return c.groups }

// Run routes a real chain step through the proved immutable image. Counts are
// written only after invocation; a caller cannot mark a host command as routed.
func (c *Controller) Run(step, tool string, args []string, stdout, stderr io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.Ready() {
		return fmt.Errorf("controlled inventory is not prepared")
	}
	if err := c.checkInputs(); err != nil {
		return err
	}
	args = append([]string(nil), args...)
	for i, arg := range args {
		if arg == c.originalInventory {
			args[i] = c.inventory
		}
	}
	if tool == "ansible-playbook" {
		hasInventory := false
		for _, arg := range args {
			if arg == "-i" {
				hasInventory = true
			}
		}
		if !hasInventory {
			args = append(append([]string{}, args...), "-i", c.inventory)
		}
	}
	var count *int
	switch step {
	case "L1 syntax check":
		count = &c.proof.Steps.Syntax
	case "L3 check-mode dry-run":
		count = &c.proof.Steps.Check
	case "L4 apply":
		count = &c.proof.Steps.Apply
	case "L5 verify":
		count = &c.proof.Steps.Verify
	case "L6 idempotency":
		count = &c.proof.Steps.Idempotency
	default:
		return fmt.Errorf("unknown controlled chain step")
	}
	if (step == "L5 verify") != (tool == "pilot") {
		return fmt.Errorf("controlled step/tool mismatch")
	}
	var output, diagnostics bytes.Buffer
	if tool == "pilot" {
		stdout = io.MultiWriter(stdout, &output)
		stderr = io.MultiWriter(stderr, &diagnostics)
	}
	err := c.execute(tool, args, stdout, stderr)
	*count++
	if tool == "pilot" {
		parsed, parseErr := ParseControllerVerifyDiagnostics(diagnostics.String())
		c.verifyDiagnostics = parsed
		if err == nil && parseErr != nil {
			return fmt.Errorf("controlled verifier diagnostic export incomplete")
		}
		if err == nil {
			verdict, ok := ParseVerifyVerdict(output.String())
			pass, fail, skip := parsed.Counts()
			if !ok || verdict.Pass != pass || verdict.Fail != fail || verdict.Skip != skip {
				c.verifyDiagnostics.Complete = false
				return fmt.Errorf("controlled verifier rows differ from summary")
			}
		}
	}
	return err
}
func (c *Controller) Finalize() (*ControllerProof, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.Ready() {
		return nil, fmt.Errorf("controller inventory not prepared")
	}
	if err := c.checkInputs(); err != nil {
		return nil, err
	}
	if err := c.probeNative(); err != nil {
		return nil, err
	}
	c.proof.PostProbeSHA256 = digestBytes(c.probe)
	out := c.proof

	return &out, nil
}

func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stageDir != "" {
		owned := c.stageDir
		_ = os.RemoveAll(owned)
		for path := range c.files {
			if strings.HasPrefix(path, owned+string(filepath.Separator)) {
				delete(c.files, path)
			}
		}
	}
	c.stageDir = ""
	c.inventory = ""
	c.originalInventory = ""
	c.ready = false
	c.closed = true
}

func readControllerKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("controlled SSH key must be a regular file")
	}
	return io.ReadAll(file)
}

func validNativeProbe(p *ControllerNativeProbe) bool {
	if p == nil || p.Go != "go version go1.26.8 linux/amd64" || p.Schema != "pilot-controller-probe/v3" || p.UID != 1000 || p.GID != 1000 || p.User != "pilot-controller" || p.Group != "pilot-controller" || p.SSHIdentity != "ssh-config/v1" || p.Ansible != "2.21.5" || p.Python != "3.14.8" || p.AnsibleOrigin != "/usr/local/lib/python3.14/site-packages/ansible/__init__.py" || p.PythonExecutable != "/usr/bin/python3.14" || p.ConfigFile != "/opt/pilot-controller/ansible.cfg" || len(p.ConfigSHA256) != 64 || p.CollectionsScanSysPath || !reflect.DeepEqual(p.Collections, []string{"/opt/pilot-controller/collections"}) || !reflect.DeepEqual(p.Roles, []string{"/opt/pilot-controller/empty"}) || len(p.Loaders) != len(ansiblePluginDirectories) {
		return false
	}
	if p.Callback != (ControllerCallback{Version: "2.1.0", Origin: "/opt/pilot-controller/collections/ansible_collections/ansible/posix/plugins/callback/json.py", SHA256: "cc2f6a845b1b7d8d87e16b7fed79b860e10ea9e9b372dd0bdcbd850b9654a032", ManifestSHA256: "3899df5b1b390f51a7fc95ad8997c7e7030daf4f5265898f96977ef9ed8d4df5", Execution: "json-command/v1"}) {
		return false
	}
	if _, err := hex.DecodeString(p.ConfigSHA256); err != nil {
		return false
	}
	expectedSys := []string{"/usr/local/lib64/python3.14/site-packages", "/usr/local/lib/python3.14/site-packages", "/usr/lib64/python314.zip", "/usr/lib64/python3.14", "/usr/lib64/python3.14/lib-dynload", "/usr/lib64/python3.14/site-packages", "/usr/lib/python3.14/site-packages"}
	if !reflect.DeepEqual(p.SysPath, expectedSys) {
		return false
	}
	for _, plugin := range ansiblePluginDirectories {
		loader, ok := p.Loaders[plugin.subdir]
		if !ok || len(loader.Paths) == 0 {
			return false
		}
		expected := []string{"/opt/pilot-controller/empty"}
		if plugin.subdir == "shell_plugins" {
			expected = []string{"shell_plugins"}
		}
		if plugin.subdir == "doc_fragments" {
			expected = []string{"/tmp/controller/home/.ansible/plugins/doc_fragments", "/usr/share/ansible/plugins/doc_fragments"}
		}
		if !reflect.DeepEqual(loader.Config, expected) {
			return false
		}
		for _, path := range loader.Paths {
			if path != "/opt/pilot-controller/empty" && path != "$CANDIDATE/shell_plugins" && path != "/tmp/controller/home/.ansible/plugins/doc_fragments" && path != "/usr/share/ansible/plugins/doc_fragments" && !strings.HasPrefix(path, "/usr/local/lib/python3.14/site-packages/ansible/") {
				return false
			}
		}
	}
	return true
}

func (c *Controller) InventoryProven() bool {
	return c.Ready() && c.proof.InventoryKind == "pilot-rendered-ssh/v1"
}

func safeControllerMount(path string) bool {
	if strings.ContainsAny(path, ",\r\n") || path == "/" {
		return false
	}
	for _, prefix := range []string{"/usr", "/opt", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/run", "/tmp/controller"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return false
		}
	}
	return true
}

func (c *Controller) VerifyDiagnostics() VerifyDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.verifyDiagnostics
	out.Rows = append([]VerifyRowDiagnostic(nil), out.Rows...)
	return out
}
