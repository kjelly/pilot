package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The --engine values of pilot reconcile.
const (
	reconcileEngineAnsible = "ansible"
	reconcileEngineGolang  = identityreconcile.EngineName
)

// golangPreviewBlockedExitCode is the exit code of a Go preview that
// produced a plan holding blocked objects (spec §2.3); any other failure
// exits 1.
const golangPreviewBlockedExitCode = 3

var (
	reconcileEngineFlag  string
	reconcilePlanOutFlag string
)

// golangDialer is the SSH side of the Go engine: sshdial.Dialer, replaced
// in tests.
type golangDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	FQDN(ctx context.Context) (string, error)
	CA(ctx context.Context) (*x509.CertPool, error)
}

var newGolangDialer = func(t sshdial.Target) golangDialer { return &sshdial.Dialer{Target: t} }

// newGolangIPAClient builds the JSON-RPC client of the preview: the
// constructor of the client, replaced in tests that wrap it. The preview
// asks it for a read-only client and nothing else.
var newGolangIPAClient = freeiparpc.New

// validateReconcileEngineFlags rejects every combination the Go engine
// does not support before anything is read (spec §2.1).
func validateReconcileEngineFlags(engine string, previewOnly, force bool, components []string, actions, planOut string) error {
	switch engine {
	case reconcileEngineAnsible:
		if planOut != "" {
			return fmt.Errorf("--plan-out 只能與 --engine %s 一起使用", reconcileEngineGolang)
		}
		return nil
	case reconcileEngineGolang:
	default:
		return fmt.Errorf("--engine 只能是 %s 或 %s", reconcileEngineAnsible, reconcileEngineGolang)
	}
	switch {
	case actions != "":
		return fmt.Errorf("--engine %s 不能與 --actions 同時使用", reconcileEngineGolang)
	case force || !previewOnly:
		return fmt.Errorf("--engine %s 目前只提供預覽：請加 --preview-only，不要加 --force", reconcileEngineGolang)
	case len(components) != 1 || components[0] != "freeipa-identity":
		return fmt.Errorf("--engine %s 只處理 --component freeipa-identity 的使用者與群組", reconcileEngineGolang)
	}
	return nil
}

// golangPreviewError carries the preview's exit code.
type golangPreviewError struct {
	err  error
	code int
}

func (e *golangPreviewError) Error() string { return e.err.Error() }
func (e *golangPreviewError) ExitCode() int { return e.code }
func (e *golangPreviewError) Unwrap() error { return e.err }

// runReconcileGolangPreview plans the users and groups of the identity
// roster with the Go engine and writes nothing to FreeIPA (spec §2.2).
func runReconcileGolangPreview(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	planOut := ""
	if reconcilePlanOutFlag != "" {
		abs, err := filepath.Abs(expandHomeDir(reconcilePlanOutFlag))
		if err != nil {
			return err
		}
		if _, err := os.Lstat(abs); err == nil {
			return fmt.Errorf("--plan-out %s 已存在；不覆寫", abs)
		}
		planOut = abs
	}
	timeout, err := parseDeployTimeout(reconcileTimeoutFlag)
	if err != nil {
		return err
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(withDeployAnsibleRuntime(cmd.Context(), runtime), timeout)
	defer cancel()

	inv := workspacePath(reconcileDirFlag, reconcileInventoryFlag)
	if err := validateFileExists(inv); err != nil {
		return err
	}
	if err := inventoryCurrentWithHosts(inv); err != nil {
		return err
	}
	snapshot, err := loadDeployInventorySnapshot(ctx, inv)
	if err != nil {
		return err
	}
	violations, err := validateDeploymentCompletenessSnapshot(inv, snapshot)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		return formatCompletenessViolations(violations)
	}
	hosts, err := resolvePatternHosts(ctx, inv, "freeipa-server", limitFlag)
	if err != nil {
		return err
	}
	if len(hosts) != 1 {
		return fmt.Errorf("freeipa-identity 需要剛好一台 freeipa-server 主機(contract hostCardinality: exactly-one)，--limit %q 之後有 %d 台：%v", limitFlag, len(hosts), hosts)
	}
	host := hosts[0]
	stage, err := golangPreviewStage(host, snapshot.Groups, stageFlag, stagingAttestedHoursFlag)
	if err != nil {
		return err
	}
	hostVars := snapshot.HostVars[host]

	rosterPath, _ := hostVars["freeipa_roster_file"].(string)
	if strings.TrimSpace(rosterPath) == "" {
		return fmt.Errorf("%s 沒有設定 freeipa_roster_file", host)
	}
	rosterPath = resolveRosterPath(filepath.Dir(inv), rosterPath)
	rosterData, err := readSecretVarsFile(ctx, rosterPath, runtime.Env)
	if err != nil {
		return fmt.Errorf("讀取 roster: %w", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(rosterData, &root); err != nil {
		return fmt.Errorf("解析 roster %s: %w", rosterPath, err)
	}
	desired, err := identityreconcile.FromRoster(root)
	if err != nil {
		return fmt.Errorf("roster %s: %w", rosterPath, err)
	}
	var vaultData []byte
	if varsFile := defaultVaultFile(inv); varsFile != "" {
		if vaultData, err = readSecretVarsFile(ctx, varsFile, runtime.Env); err != nil {
			return fmt.Errorf("讀取 vault vars 檔: %w", err)
		}
	}
	password, err := inventory.ResolveIPAAdminPassword(vaultData, rosterData)
	if err != nil {
		return err
	}
	target, err := sshTargetFromHostVars(host, hostVars)
	if err != nil {
		return err
	}

	dialer := newGolangDialer(target)
	fqdn, err := dialer.FQDN(ctx)
	if err != nil {
		return fmt.Errorf("讀取 %s 的 FQDN: %w", host, err)
	}
	if declared := rosterServer(root); declared != "" && !strings.EqualFold(declared, fqdn) {
		return fmt.Errorf("roster freeipa.server 是 %s，但 %s 的 hostname -f 是 %s", declared, host, fqdn)
	}
	ca, err := dialer.CA(ctx)
	if err != nil {
		return fmt.Errorf("讀取 %s 的 IPA CA: %w", host, err)
	}
	client, err := newGolangIPAClient(freeiparpc.Config{FQDN: fqdn, CA: ca, DialContext: dialer.DialContext, ReadOnly: true})
	if err != nil {
		return err
	}
	if err := client.Login(ctx, desired.Principal, password); err != nil {
		return fmt.Errorf("登入 FreeIPA: %w", err)
	}
	defer func() { _ = client.Logout(context.Background()) }()
	server, err := client.CheckServer(ctx)
	if err != nil {
		return err
	}
	observedAt := time.Now()
	obs, err := identityreconcile.Observe(ctx, client, desired.Principal)
	if err != nil {
		return err
	}
	plan := identityreconcile.Build(desired, obs.Users, obs.Groups)
	stats := client.Stats()
	doc := identityreconcile.NewDocument(desired, obs, plan,
		identityreconcile.Target{
			InventoryHost: host, FQDN: fqdn, Destination: sshdial.DefaultDestination,
			SSH: identityreconcile.SSHTarget{Host: target.Host, Port: target.Port, User: target.User},
		},
		identityreconcile.Server{Version: server.ServerVersion, APIVersion: server.APIVersion},
		pilotRevision(), observedAt,
		identityreconcile.Stats{HTTPRequests: stats.HTTPRequests, Reads: stats.Reads, Writes: stats.Writes, Relogins: stats.Relogins, ReadRetries: stats.ReadRetries},
	)
	printGolangPreview(out, doc, stage)
	if planOut != "" {
		if err := writeGolangPlan(planOut, doc); err != nil {
			return err
		}
		fmt.Fprintf(out, "plan JSON：%s\n", planOut)
	}
	if doc.Stats.Writes != 0 {
		return fmt.Errorf("內部錯誤：預覽送出了 %d 個寫入", doc.Stats.Writes)
	}
	if doc.Result == identityreconcile.ResultBlocked {
		return &golangPreviewError{err: fmt.Errorf("--engine %s 預覽：%d 個物件被阻擋，見上方清單", reconcileEngineGolang, len(doc.Blocked)), code: golangPreviewBlockedExitCode}
	}
	return nil
}

// inventoryCurrentWithHosts fails when a sibling hosts.yml renders to a
// different inventory: the Ansible path regenerates it, a read-only
// preview must not write it.
func inventoryCurrentWithHosts(inv string) error {
	dir, err := filepath.Abs(filepath.Dir(inv))
	if err != nil {
		return err
	}
	hostsPath := filepath.Join(dir, "hosts.yml")
	absInv, err := filepath.Abs(inv)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(hostsPath)
	if hostsPath == absInv || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return err
	}
	rendered, err := generateInventoryFromHosts(hf)
	if err != nil {
		return err
	}
	current, err := os.ReadFile(absInv)
	if err != nil {
		return err
	}
	if string(current) != rendered {
		return fmt.Errorf("%s 與 hosts.yml 不一致；--engine %s 是唯讀預覽，不會重新產生 inventory：請先執行 pilot inventory generate", inv, reconcileEngineGolang)
	}
	return nil
}

// golangPreviewStage applies the playbook's stage gates (AGENTS.md §4.3):
// a host in the prod or staging group needs that stage, and a staging or
// prod stage needs a host in that group. --stage on the command line is
// the confirmation, as for the Ansible engine; prod needs an attestation.
func golangPreviewStage(host string, groups map[string][]string, stage, attestedHours string) (string, error) {
	if stage == "" {
		stage = "sandbox"
	}
	in := func(group string) bool { return slices.Contains(groups[group], host) }
	switch {
	case in("prod") && stage != "prod":
		return "", fmt.Errorf("%s 在 prod group，但 stage 是 %s：請加 --stage prod", host, stage)
	case in("staging") && stage != "staging":
		return "", fmt.Errorf("%s 在 staging group，但 stage 是 %s：請加 --stage staging", host, stage)
	case (stage == "staging" || stage == "prod") && !in(stage):
		return "", fmt.Errorf("stage %s 需要 %s 在 %s group", stage, host, stage)
	}
	if stage == "prod" {
		hours, err := strconv.Atoi(attestedHours)
		if err != nil || hours < 0 || hours > 168 {
			return "", fmt.Errorf("--stage prod 需要 --staging-attested-within-hours 0–168")
		}
	}
	return stage, nil
}

// readSecretVarsFile reads a vars file, decrypting an ansible-vault file
// in memory with the secret ansible-playbook would find (spec §3). The
// decryption is bounded by ctx, the preview's --timeout.
func readSecretVarsFile(ctx context.Context, path string, env []string) ([]byte, error) {
	if isVaultEncrypted(path) {
		return inventory.ViewVaultFileAmbient(ctx, path, env)
	}
	return os.ReadFile(path)
}

func rosterServer(root map[string]any) string {
	fi, _ := root["freeipa"].(map[string]any)
	s, _ := fi["server"].(string)
	return strings.TrimSpace(s)
}

// Host variables that change the SSH connection and that the Go engine
// does not support: it refuses them rather than connect differently from
// Ansible (spec §4).
var unsupportedSSHHostVars = []string{
	"ansible_password", "ansible_ssh_pass", "ansible_ssh_password",
	"ansible_ssh_host", "ansible_ssh_port", "ansible_ssh_user",
	"ansible_private_key_file", "ansible_ssh_executable",
}

// multiplexOptions are the only options ansible_ssh_args may carry: they
// tune Ansible's connection reuse, which the Go tunnel does on its own.
var multiplexOptions = map[string]bool{"ControlMaster": true, "ControlPath": true, "ControlPersist": true}

// sshTargetFromHostVars builds the tunnel's SSH target from the effective
// host variables (spec §4).
func sshTargetFromHostVars(host string, vars map[string]any) (sshdial.Target, error) {
	var t sshdial.Target
	for _, key := range unsupportedSSHHostVars {
		if v, ok := vars[key]; ok && v != nil && v != "" {
			return t, fmt.Errorf("%s 設定了 %s；--engine %s 不支援", host, key, reconcileEngineGolang)
		}
	}
	if c, ok := vars["ansible_connection"]; ok && c != nil && c != "ssh" {
		return t, fmt.Errorf("%s 的 ansible_connection 是 %v；--engine %s 只支援 ssh", host, c, reconcileEngineGolang)
	}
	t.Host = host
	if h, ok := vars["ansible_host"].(string); ok && h != "" {
		t.Host = h
	}
	if u, ok := vars["ansible_user"].(string); ok {
		t.User = u
	}
	if k, ok := vars["ansible_ssh_private_key_file"].(string); ok {
		t.IdentityFile = expandHomeDir(k)
	}
	if p, ok := vars["ansible_port"]; ok && p != nil {
		port, err := strconv.Atoi(fmt.Sprint(p))
		if err != nil {
			return t, fmt.Errorf("%s 的 ansible_port %v 不是整數", host, p)
		}
		t.Port = port
	}
	t.Options = map[string]string{}
	for _, key := range []string{"ansible_ssh_common_args", "ansible_ssh_extra_args"} {
		opts, err := sshOptionArgs(vars[key])
		if err != nil {
			return t, fmt.Errorf("%s 的 %s：%w", host, key, err)
		}
		for k, v := range opts {
			t.Options[k] = v
		}
	}
	opts, err := sshOptionArgs(vars["ansible_ssh_args"])
	if err != nil {
		return t, fmt.Errorf("%s 的 ansible_ssh_args：%w", host, err)
	}
	for k := range opts {
		if !multiplexOptions[k] {
			return t, fmt.Errorf("%s 的 ansible_ssh_args 含 %s；只接受 ControlMaster、ControlPath、ControlPersist", host, k)
		}
	}
	if err := t.Validate(); err != nil {
		return t, fmt.Errorf("%s：%w", host, err)
	}
	return t, nil
}

// sshOptionArgs reads "-o Key=Value" arguments; anything else is refused.
func sshOptionArgs(v any) (map[string]string, error) {
	out := map[string]string{}
	if v == nil || v == "" {
		return out, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("不是字串")
	}
	words, err := splitShellWords(s)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(words); i++ {
		w := words[i]
		var opt string
		switch {
		case w == "-o" && i+1 < len(words):
			i++
			opt = words[i]
		case strings.HasPrefix(w, "-o") && len(w) > 2:
			opt = w[2:]
		default:
			return nil, fmt.Errorf("只接受 -o Key=Value，不接受 %q", w)
		}
		key, value, ok := strings.Cut(opt, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("-o %q 不是 Key=Value", opt)
		}
		out[key] = value
	}
	return out, nil
}

// splitShellWords splits on blanks, honoring single and double quotes.
func splitShellWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words, inWord = append(words, cur.String()), false
				cur.Reset()
			}
		case r == '\\':
			return nil, fmt.Errorf("不支援反斜線跳脫")
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("引號沒有成對")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

func pilotRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	revision, modified := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "unknown"
	}
	if modified {
		revision += "+modified"
	}
	return revision
}

func printGolangPreview(out io.Writer, doc identityreconcile.Document, stage string) {
	fmt.Fprintf(out, "═══ pilot reconcile --engine %s — 唯讀預覽（不寫入 FreeIPA）═══\n", doc.Engine.Name)
	fmt.Fprintf(out, "範圍：%s　stage：%s　目標：%s（%s）　FreeIPA %s／API %s\n",
		doc.Scope, stage, doc.Target.InventoryHost, doc.Target.FQDN, doc.Server.Version, doc.Server.APIVersion)
	fmt.Fprintf(out, "讀到 %d 位使用者、%d 個群組\n", doc.Observation.Users, doc.Observation.Groups)
	counts := map[string]int{}
	for _, op := range doc.Operations {
		counts[op.Kind]++
	}
	if len(doc.Operations) == 0 {
		fmt.Fprintln(out, "計畫：沒有任何寫入")
	} else {
		fmt.Fprintf(out, "計畫：%d 個寫入\n", len(doc.Operations))
		for _, kind := range identityreconcile.Kinds {
			if counts[kind] > 0 {
				fmt.Fprintf(out, "  %-28s %d\n", kind, counts[kind])
			}
		}
		for _, op := range doc.Operations {
			if op.Destructive {
				fmt.Fprintf(out, "  ⚠️  %s %s（破壞性）\n", op.Kind, op.Object)
			}
		}
	}
	for _, b := range doc.Blocked {
		fmt.Fprintf(out, "🚫 阻擋 %s：%s — %s\n", b.Object, b.Reason, b.Detail)
	}
	for _, r := range doc.Reports.SSHKeys {
		fmt.Fprintf(out, "ℹ️  %s 的 SSH key 與 roster 不同（由 Ansible engine 處理）\n", r.User)
	}
	for _, r := range doc.Reports.ImplicitMembershipPrune {
		fmt.Fprintf(out, "ℹ️  %s 沒有宣告 %s 成員：authoritative 會撤銷這類的所有直接成員\n", r.Group, strings.Join(r.Kinds, "、"))
	}
	if len(doc.Reports.NotInScope) > 0 {
		sections := slices.Clone(doc.Reports.NotInScope)
		sort.Strings(sections)
		fmt.Fprintf(out, "ℹ️  不在 Go engine 範圍（由 Ansible engine 處理）：%s\n", strings.Join(sections, ", "))
	}
	fmt.Fprintf(out, "讀取：%d 個 HTTP 請求、%d 個讀取、%d 個寫入\n", doc.Stats.HTTPRequests, doc.Stats.Reads, doc.Stats.Writes)
}

func writeGolangPlan(path string, doc identityreconcile.Document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("--plan-out: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
