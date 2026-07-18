// deploy.go implements `pilot deploy`, an interactive promptui wizard
// that lets someone unfamiliar with Ansible run a real deployment
// without hand-assembling an `ansible-playbook ...` command line.
//
// It does not reimplement any deployment logic — it only walks the
// user through the same decisions DELIVERY.md documents (inventory
// path, preflight, full-site vs. single-component, stage gate,
// vault secrets, dry-run vs. apply) and then shells out to
// ansible-playbook via internal/ansible.Runner, streaming output live.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/contract"
	"github.com/anomalyco/pilot/internal/delivery"
	"github.com/anomalyco/pilot/internal/spec"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/tools"
)

var deployInventoryFlag string
var deployTimeoutFlag string
var deployActionFlag string

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "互動式部署精靈 — 不需要熟悉 ansible-playbook 也能佈署",
	Long: `pilot deploy 用問答的方式引導你完成一次佈署：挑 inventory、挑要
套用的元件(或全站)、挑 stage(sandbox/staging/prod)、決定要不要先預覽
(--check --diff)，最後才真正執行 ansible-playbook，過程全程印出真實輸出。

這是 DELIVERY.md 手動組指令的替代路徑，行為完全一致(同一套 stage/confirm
gate、同一份 Playbook 對照表)——熟悉 Ansible 的人仍可以照 DELIVERY.md 手動執行。`,
	RunE: runDeploy,
}

func init() {
	deployCmd.Flags().StringVarP(&deployInventoryFlag, "inventory", "i", "inventory.yml", "預先填入的 inventory 路徑(精靈仍會再問一次，可直接按 Enter 採用)")
	deployCmd.Flags().StringVar(&deployTimeoutFlag, "timeout", "30m", "每次 ansible-playbook 呼叫(preflight/預覽/套用，各自獨立計時)的逾時上限，Go duration 格式(例如 45m、1h30m)；跑得比這個久會被強制中止")
	deployCmd.Flags().StringVar(&deployActionFlag, "action", "apply", "contract lifecycle action: apply, upgrade, or decommission (only declared actions may run)")
	rootCmd.AddCommand(deployCmd)
}

// errDeployAborted marks a wizard step the user explicitly cancelled
// (Ctrl-C, Ctrl-D, or a "no" on a safety confirmation). runDeploy
// treats it as a clean, silent exit rather than a real failure.
var errDeployAborted = errors.New("已取消")

// errPreflightRejected distinguishes stopping after a failed preflight from a clean cancellation.
var errPreflightRejected = errors.New("前置檢查失敗，已停止部署")

func runDeploy(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("pilot deploy 需要互動式終端機(TTY)才能問問題；非互動場景請直接用 ansible-playbook（見 DELIVERY.md）")
	}

	timeout, err := parseDeployTimeout(deployTimeoutFlag)
	if err != nil {
		return err
	}

	runner := ansible.NewRunner()
	runner.Timeout = timeout
	runner.StdoutWriter = out
	runner.StderrWriter = cmd.ErrOrStderr()

	fmt.Fprintln(out, "═══ pilot deploy — 互動式部署精靈 ═══")
	fmt.Fprintln(out, "每一步都可以直接按 Enter 採用預設值；Ctrl-C 隨時可以取消。")
	fmt.Fprintln(out)

	inv, err := runTextProgram("Inventory 檔路徑", deployInventoryFlag, validateFileExists)
	if err != nil {
		return abortOrErr(err)
	}

	if runConfirmProgram("要不要先看一下這份 inventory 的 host/group 結構？(ansible-inventory --graph)", true) {
		previewInventoryGraph(cmd.Context(), out, inv)
		fmt.Fprintln(out)
	}

	ok, err := runPreflight(cmd.Context(), runner, out, inv)
	if err != nil {
		return abortOrErr(err)
	}
	if !ok {
		return errPreflightRejected
	}

	scopeIdx, err := runSelectProgram("要佈署什麼？", []string{
		"全站部署(site.yml) — 一次套用 inventory 裡已經填好機器的所有元件",
		"單一元件 — 從清單挑一支 apply playbook",
	})
	if err != nil {
		return abortOrErr(err)
	}

	if scopeIdx == 0 {
		err = runSiteDeploy(cmd.Context(), runner, out, inv)
	} else {
		err = runSinglePlaybookDeploy(cmd.Context(), runner, out, inv)
	}
	return abortOrErr(err)
}

// parseDeployTimeout validates the --timeout flag value used as
// ansible.Runner's per-invocation (preflight/preview/apply, each
// timed independently) wall-clock ceiling. ansible.NewRunner defaults
// this to 30 minutes with no override anywhere in the call chain
// (see internal/ansible/runner.go) — a real apply that runs longer
// than that on a slower host or heavier topology gets silently
// SIGKILLed mid-run with no warning. This flag lets a caller raise
// (or lower) it instead of falling back to a manual ansible-playbook
// invocation outside pilot deploy.
func parseDeployTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("--timeout 不是合法的 duration(例如 45m、1h30m)：%q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("--timeout 必須是正數：%q", s)
	}
	return d, nil
}

// abortOrErr swallows errDeployAborted (and errors wrapping it) so a
// user-initiated cancel exits 0 instead of printing a scary "Error:".
func abortOrErr(err error) error {
	if errors.Is(err, errDeployAborted) {
		return nil
	}
	return err
}

// ---- shared prompt helpers -------------------------------------------------
//
// The actual prompt/select/confirm screens live in deploy_tui.go now
// (runSelectProgram/runTextProgram/runConfirmProgram, on top of the
// shared Bubble Tea primitives in tui_select.go/tui_textinput.go/
// tui_confirm.go) — what's left here is dumpMenuDebug (called from
// newSelectModel, tui_select.go) and the validators every prompt call
// site still uses.

// dumpMenuDebug prints label's live item list, one per line with its
// 0-based DOWN-arrow index, to stderr. It exists for scripted/`trec`-
// driven runs: several of this wizard's menus (group_vars keys, vault
// keys, host lists) have an item count that depends on file contents
// rather than fixed source order, so a script computing `DOWN <n>`
// from a source-code read (or a remembered prior session) can silently
// miscount. Setting PILOT_DEBUG_MENU=1 lets a driving script/agent read
// the real item list straight from the recorded terminal output instead
// of recomputing or eyeballing it. Gated behind the env var so normal
// interactive use (and the rendered menu itself) is unaffected.
func dumpMenuDebug(label string, items []string) {
	fmt.Fprintf(os.Stderr, "[pilot:menu] %s (%d 項，DOWN <n> 從 0 起算)\n", label, len(items))
	for i, item := range items {
		fmt.Fprintf(os.Stderr, "[pilot:menu]   %d: %s\n", i, item)
	}
}

func validateFileExists(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("不能留空")
	}
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("找不到檔案: %s", p)
	}
	return nil
}

func validateOptionalKV(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, tok := range strings.Fields(s) {
		if !strings.Contains(tok, "=") {
			return fmt.Errorf("%q 不是 key=value 格式", tok)
		}
	}
	return nil
}

func validateHoursWithinWeek(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("請輸入數字(小時)")
	}
	if n < 0 || n > 168 {
		return fmt.Errorf("必須是 0-168 之間(超過 7 天視為沒有效的 staging 驗證)")
	}
	return nil
}

// ---- inventory preview / preflight -----------------------------------------

func previewInventoryGraph(ctx context.Context, out io.Writer, inv string) {
	r := ansible.NewRunner()
	r.Binary = "ansible-inventory"
	r.StdoutWriter = out
	res, err := r.Run(ctx, "-i", inv, "--graph")
	if err != nil {
		fmt.Fprintf(out, "(無法執行 ansible-inventory：%v)\n", err)
		return
	}
	if res.ExitCode != 0 {
		fmt.Fprintf(out, "(ansible-inventory 結束碼 %d，上面輸出可能有錯誤訊息)\n", res.ExitCode)
	}
}

// runPreflight offers to run playbooks/preflight.yml before anything
// else is applied. Returns ok=false when the user chose to stop
// instead of continuing past a failed (or skipped) preflight.
func runPreflight(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string) (bool, error) {
	idx, err := runSelectProgram("要先跑前置檢查(preflight)嗎？", []string{
		"完整前置檢查(含 SSH 連線測試)",
		"只做靜態檢查(機器還沒開機/還連不上時用；不連線)",
		"跳過前置檢查",
	})
	if err != nil {
		return false, err
	}
	if idx == 2 {
		return true, nil
	}
	fmt.Fprintln(out, "── 執行 playbooks/preflight.yml ──")
	args := []string{"playbooks/preflight.yml", "-i", inv}
	if idx == 1 {
		args = append(args, "--tags", "static")
	}
	res, err := runner.Run(ctx, args...)
	if err != nil {
		return false, fmt.Errorf("執行 preflight 失敗: %w", err)
	}
	fmt.Fprintln(out)
	if res.ExitCode == 0 {
		fmt.Fprintln(out, "✅ 前置檢查通過")
		return true, nil
	}
	fmt.Fprintf(out, "❌ 前置檢查沒有全過(結束碼 %d)\n", res.ExitCode)
	return runConfirmProgram("仍要繼續佈署嗎？(不建議 — 上面的錯誤通常代表 inventory 填錯或連不上機器)", false), nil
}

// ---- stage gate -------------------------------------------------------------

// stageDecision is the outcome of asking "sandbox / staging / prod",
// already carrying whatever confirm_* / attestation vars that choice
// requires. The caller still has to attach the stage value itself
// under the right variable name (stage vs. patch_stage for
// os-patch-sla, or both when driving the aggregate site.yml).
type stageDecision struct {
	Stage       string
	ConfirmVars []string // e.g. []string{"confirm_staging=true"}
}

func promptStageDecision(out io.Writer, context string) (stageDecision, error) {
	idx, err := runSelectProgram(fmt.Sprintf("[%s] 要套用到哪個 stage？", context), []string{
		"sandbox（預設；沙盒/測試機，不需要額外確認）",
		"staging（測試環境，需要額外確認）",
		"prod（正式環境，需要額外確認 + 近 7 天內的 staging 驗證證明）",
	})
	if err != nil {
		return stageDecision{}, err
	}
	switch idx {
	case 0:
		return stageDecision{Stage: "sandbox"}, nil
	case 1:
		fmt.Fprintln(out, "⚠️  即將對已歸類進 staging 的機器套用真正的變更。")
		if !runConfirmProgram("確定要繼續嗎？", false) {
			return stageDecision{}, errDeployAborted
		}
		return stageDecision{Stage: "staging", ConfirmVars: []string{"confirm_staging=true"}}, nil
	case 2:
		fmt.Fprintln(out, "⚠️  即將對已歸類進 prod 的機器套用真正的變更。")
		hours, err := runTextProgram("上次 staging 驗證距今幾小時？(0-168，即 7 天內)", "24", validateHoursWithinWeek)
		if err != nil {
			return stageDecision{}, err
		}
		_, err = runTextProgram(`為避免手滑，請輸入大寫 "PROD" 以確認要套用到正式環境`, "", func(s string) error {
			if s != "PROD" {
				return fmt.Errorf(`必須完全輸入 "PROD"`)
			}
			return nil
		})
		if err != nil {
			return stageDecision{}, err
		}
		return stageDecision{
			Stage:       "prod",
			ConfirmVars: []string{"confirm_prod=true", "staging_attested_within_hours=" + hours},
		}, nil
	}
	return stageDecision{}, fmt.Errorf("unreachable")
}

// ---- seaweedfs-s3 signed-mode config -----------------------------------------

// defaultSeaweedfsS3ConfigPath is the target-host path seaweedfs-s3-apply.yml
// renders s3.json to (the container-side path is fixed; only this host-side
// bind-mount path is configurable). Matches the convention already used in
// inventories/jelly/group_vars/seaweedfs-s3.yml.
const defaultSeaweedfsS3ConfigPath = "/etc/seaweedfs/s3.json"

// promptSeaweedfsS3Config asks whether to enable SeaweedFS's signed-mode S3
// identity (vs. the sandbox-default anonymous access) and, if so, returns the
// -e seaweedfs_s3_config_path=<path> var — the playbook renders s3.json
// itself from restic_aws_access_key_id/secret (vault), so this is just the
// host-side path, never a locally-authored file. stage=prod already refuses
// anonymous access (see seaweedfs-s3-apply.yml's prod gate), so that case
// skips straight to asking for the path instead of offering to opt out.
func promptSeaweedfsS3Config(out io.Writer, stage string) ([]string, error) {
	defaultPath := defaultSeaweedfsS3ConfigPath
	if stage == "prod" {
		fmt.Fprintln(out, "ℹ️  stage=prod 不允許匿名 S3 存取，一定要設定簽章模式(seaweedfs_s3_config_path)。")
		path, err := runTextProgram("s3.json 在目標主機上的路徑", defaultPath, nil)
		if err != nil {
			return nil, err
		}
		return []string{"seaweedfs_s3_config_path=" + path}, nil
	}

	idx, err := runSelectProgram("要不要啟用簽章模式 S3 存取？(sandbox 預設可以先跳過，用匿名存取)", []string{
		"不要 — 先用匿名存取(僅適合 sandbox，不建議正式環境)",
		"要 — 啟用簽章模式(identity 憑證沿用 restic_aws_access_key_id / restic_aws_secret_access_key，走 vault)",
	})
	if err != nil {
		return nil, err
	}
	if idx == 0 {
		return nil, nil
	}
	path, err := runTextProgram("s3.json 在目標主機上的路徑", defaultPath, nil)
	if err != nil {
		return nil, err
	}
	return []string{"seaweedfs_s3_config_path=" + path}, nil
}

// ---- cross-role host address auto-detect --------------------------------------
//
// Several apply playbooks take an "IP/FQDN of some other role's host"
// variable (restic_s3_target_host, siem_forward_host, wazuh_manager_host,
// loki_target_host, thanos_s3_target_host, alertmanager_target_host,
// thanos_query_target_host, …), each following the same "that role lives in
// exactly one inventory group" convention. resolveGroupHost/promptAutoHostVar
// below is the one mechanism deployCatalog's autoHostVar entries drive,
// rather than one bespoke resolver per role.

// resolveGroupHost asks ansible-inventory for the first host in inv's named
// group and its ansible_host, so `pilot deploy` can default a variable like
// restic_s3_target_host to it instead of making the user look the address
// up themselves. Returns ok=false for anything that stops it from resolving
// cleanly — missing ansible-inventory, an empty/absent group, unparseable
// JSON — since the caller's fallback (ask the user directly) covers all of
// those.
func resolveGroupHost(ctx context.Context, inv, group string) (host string, ok bool) {
	r := ansible.NewRunner()
	r.Binary = "ansible-inventory"
	res, err := r.Run(ctx, "-i", inv, "--list")
	if err != nil || res.ExitCode != 0 {
		return "", false
	}
	return parseGroupHostFromInventoryList(res.Stdout, group)
}

// parseGroupHostFromInventoryList pulls the first host of the named group
// (and its ansible_host, if set) out of `ansible-inventory --list`'s JSON.
// Split out from resolveGroupHost so the parsing logic is testable without
// shelling out to ansible-inventory.
func parseGroupHostFromInventoryList(listJSON, group string) (host string, ok bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(listJSON), &raw); err != nil {
		return "", false
	}

	var groupData struct {
		Hosts []string `json:"hosts"`
	}
	groupJSON, present := raw[group]
	if !present {
		return "", false
	}
	if err := json.Unmarshal(groupJSON, &groupData); err != nil || len(groupData.Hosts) == 0 {
		return "", false
	}

	var meta struct {
		HostVars map[string]map[string]any `json:"hostvars"`
	}
	if err := json.Unmarshal(raw["_meta"], &meta); err == nil {
		if hv, ok := meta.HostVars[groupData.Hosts[0]]; ok {
			if ah, ok := hv["ansible_host"].(string); ok && ah != "" {
				return ah, true
			}
		}
	}
	return groupData.Hosts[0], true
}

// siteAutoHostVars returns every distinct cross-role host variable the
// deploy catalog knows how to auto-detect, deduped by Var in catalog order
// (siem_forward_host and thanos_s3_target_host each appear under two
// components, always with the same source group). The site-wide flow walks
// this list so site.yml runs get the same auto-detection the
// single-component wizard has — before 2026-07-17 only the latter offered
// it, and a site-wide deploy silently relied on the user hand-typing every
// cross-role -e.
func siteAutoHostVars() []autoHostVar {
	seen := make(map[string]bool)
	var out []autoHostVar
	for _, p := range deployCatalog {
		for _, av := range p.AutoHostVars {
			if seen[av.Var] {
				continue
			}
			seen[av.Var] = true
			out = append(out, av)
		}
	}
	return out
}

// promptAutoHostVar fills in -e <av.Var>=<ip> automatically when it can
// resolve av.Group's host from inv, falling back to a manual prompt (blank
// = skip; the target playbook treats an unset value however it already
// does today — a hard gate failure for a required destination, or a silent
// feature-skip for an optional one).
func promptAutoHostVar(ctx context.Context, out io.Writer, inv string, av autoHostVar) ([]string, error) {
	if host, ok := resolveGroupHost(ctx, inv, av.Group); ok {
		q := fmt.Sprintf("偵測到這份 inventory 的 %s：%s，這次要用它嗎？(-e %s=%s)", av.Label, host, av.Var, host)
		if runConfirmProgram(q, true) {
			return []string{av.Var + "=" + host}, nil
		}
	}
	path, err := runTextProgram(
		fmt.Sprintf("%s 的 IP/FQDN(-e %s；留空 = 跳過)", av.Label, av.Var),
		"", nil,
	)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	return []string{av.Var + "=" + path}, nil
}

// ---- vault / secrets --------------------------------------------------------

type vaultInput struct {
	ExtraVarsFile     string // -e @<file>
	VaultPasswordFile string // --vault-password-file <file>
	AskVaultPass      bool   // --ask-vault-pass (needs stdin wired to the terminal)
}

// defaultVaultFile returns the conventional vault vars file path next to an
// inventory (<inventory 目錄>/.vault/main.yaml — see `pilot inventory
// generate`'s skeleton output), or "" if no file exists there.
func defaultVaultFile(inv string) string {
	candidate := filepath.Join(filepath.Dir(inv), ".vault", "main.yaml")
	if _, err := os.Stat(candidate); err != nil {
		return ""
	}
	return candidate
}

// ansibleVaultHeaderPrefix is the fixed literal ansible-vault writes as the
// first bytes of any file it encrypts (e.g. "$ANSIBLE_VAULT;1.1;AES256\n").
// ansible-vault always encrypts the whole file, never just a value inside
// it, so checking this prefix is a reliable way to tell an encrypted vars
// file from a plaintext one without needing the password.
const ansibleVaultHeaderPrefix = "$ANSIBLE_VAULT;"

// isVaultEncrypted reports whether path looks like an ansible-vault
// encrypted file. A read failure (missing/unreadable file) is treated as
// "not encrypted" — validateFileExists already guarantees the path exists
// by the time this is called, and the ansible-playbook run itself is the
// real gate on the file actually being readable.
func isVaultEncrypted(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(ansibleVaultHeaderPrefix))
	n, _ := io.ReadFull(f, buf)
	return n == len(buf) && string(buf) == ansibleVaultHeaderPrefix
}

func promptVault(out io.Writer, inv, hint string) (vaultInput, error) {
	if hint != "" {
		fmt.Fprintf(out, "ℹ️  這個元件通常需要：%s\n", hint)
	}

	varsFile := ""
	autoFile := defaultVaultFile(inv)
	if autoFile != "" {
		if runConfirmProgram(fmt.Sprintf("偵測到 %s，這次佈署要用它當密碼變數檔嗎？", autoFile), true) {
			varsFile = autoFile
		}
	}

	if varsFile == "" {
		idx, err := runSelectProgram("這次佈署需要密碼變數嗎？(例如 FreeIPA/Keycloak 的管理密碼，走 ansible-vault 加密檔)", []string{
			"不需要",
			"需要 — 我有一份 ansible-vault 加密的 vars 檔",
		})
		if err != nil {
			return vaultInput{}, err
		}
		if idx == 0 {
			return vaultInput{}, nil
		}
		varsFile, err = runTextProgram("vars 檔路徑(ansible-vault 加密過的 yaml)", "", validateFileExists)
		if err != nil {
			return vaultInput{}, err
		}
	}

	if !isVaultEncrypted(varsFile) {
		fmt.Fprintf(out, "ℹ️  %s 沒有加密(不是 ansible-vault 格式)，略過密碼詢問。\n", varsFile)
		return vaultInput{ExtraVarsFile: varsFile}, nil
	}

	decryptIdx, err := runSelectProgram("怎麼解密？", []string{
		"用密碼檔(--vault-password-file)",
		"執行時手動輸入密碼(--ask-vault-pass)",
	})
	if err != nil {
		return vaultInput{}, err
	}
	if decryptIdx == 1 {
		return vaultInput{ExtraVarsFile: varsFile, AskVaultPass: true}, nil
	}
	passFile, err := runTextProgram("vault 密碼檔路徑", "", validateFileExists)
	if err != nil {
		return vaultInput{}, err
	}
	return vaultInput{ExtraVarsFile: varsFile, VaultPasswordFile: passFile}, nil
}

func (v vaultInput) args() []string {
	var out []string
	if v.ExtraVarsFile != "" {
		out = append(out, "-e", "@"+v.ExtraVarsFile)
	}
	if v.VaultPasswordFile != "" {
		out = append(out, "--vault-password-file", v.VaultPasswordFile)
	}
	if v.AskVaultPass {
		out = append(out, "--ask-vault-pass")
	}
	return out
}

// ---- execution: dry-run first, then optionally apply -----------------------

var confirmDeployment = runConfirmProgram

// executeDeployment builds the final ansible-playbook argv from the
// choices gathered by the caller, offers a --check --diff preview
// first, and — only if that preview succeeds and the user asks for it
// — re-runs the same command for real. A failed preview or apply returns
// an error so pilot deploy exits non-zero; a clean user cancellation
// before a failed step remains a successful exit.
func executeDeployment(ctx context.Context, runner *ansible.Runner, out io.Writer, playbook, inv, limit, tags string, extraVars []string, vault vaultInput) error {
	return executeDeploymentTransaction(ctx, runner, out, playbook, inv, limit, tags, extraVars, vault, deploymentTransactionOptions{})
}

type deploymentTransactionOptions struct {
	Writer         delivery.EventWriter
	Preflight      delivery.StepFunc
	PrepareApply   delivery.StepFunc
	Verify         delivery.StepFunc
	Rollback       delivery.StepFunc
	Stage          string
	Idempotency    delivery.IdempotencyPolicy
	RollbackPolicy delivery.RollbackPolicy
}

// executeDeploymentTransaction is the single preview→apply→verify path for
// interactive deploy. Keeping prompt cancellation as a typed transaction
// outcome preserves the historical exit-0 cancellation contract while still
// finalizing an evidence run when one was started.
func executeDeploymentTransaction(ctx context.Context, runner *ansible.Runner, out io.Writer, playbook, inv, limit, tags string, extraVars []string, vault vaultInput, options deploymentTransactionOptions) error {
	baseArgs := []string{playbook, "-i", inv}
	if limit != "" {
		baseArgs = append(baseArgs, "--limit", limit)
	}
	if tags != "" {
		baseArgs = append(baseArgs, "--tags", tags)
	}
	for _, v := range extraVars {
		baseArgs = append(baseArgs, "-e", v)
	}
	baseArgs = append(baseArgs, vault.args()...)

	if vault.AskVaultPass {
		runner.Stdin = os.Stdin
	}

	dryRunFirst := confirmDeployment("要先預覽(--check --diff)再決定要不要真的套用嗎？", true)

	runOnce := func(check, confirm bool) (*ansible.Result, error) {
		mode := "套用"
		args := baseArgs
		if check {
			mode = "預覽(--check --diff)"
			args = append([]string{"--check", "--diff"}, baseArgs...)
		}
		fmt.Fprintf(out, "\n▶ %s：ansible-playbook %s\n\n", mode, strings.Join(args, " "))
		if confirm && !confirmDeployment("確定要執行以上指令嗎？", true) {
			return nil, delivery.ErrCancelled
		}
		return runner.Run(ctx, args...)
	}

	preview := delivery.StepFunc(nil)
	if dryRunFirst {
		preview = func(ctx context.Context) error {
			res, err := runOnce(true, true)
			if err != nil {
				return err
			}
			fmt.Fprintln(out)
			if res.ExitCode != 0 {
				return fmt.Errorf("❌ 預覽失敗(結束碼 %d)，請看上面的輸出修正後再重新執行 pilot deploy", res.ExitCode)
			}
			fmt.Fprintln(out, "✅ 預覽完成，沒有錯誤。")
			return nil
		}
	}
	apply := func(ctx context.Context) error {
		if dryRunFirst {
			if !confirmDeployment("預覽看起來沒問題，要接著套用真正的變更嗎？", false) {
				fmt.Fprintln(out, "先在這裡停下來，沒有套用任何變更。")
				return delivery.ErrCancelled
			}
		} else if !confirmDeployment("確定要執行以上指令嗎？", true) {
			return delivery.ErrCancelled
		}
		if options.PrepareApply != nil {
			if err := options.PrepareApply(ctx); err != nil {
				return err
			}
		}
		res, err := runOnce(false, dryRunFirst)
		if err != nil {
			return err
		}
		fmt.Fprintln(out)
		if res.ExitCode != 0 {
			return fmt.Errorf("❌ 套用失敗(結束碼 %d)，請看上面的輸出", res.ExitCode)
		}
		fmt.Fprintln(out, "✅ 套用完成。")
		return nil
	}
	idempotency := delivery.StepFunc(nil)
	if options.Idempotency == delivery.IdempotencyAlways || options.Idempotency == delivery.IdempotencyStageGTEStaging {
		idempotency = func(ctx context.Context) error {
			fmt.Fprintln(out, "▶ 冪等性檢查：重新套用相同 playbook")
			res, err := runner.Run(ctx, baseArgs...)
			if err != nil {
				return fmt.Errorf("執行冪等性檢查失敗: %w", err)
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("冪等性檢查失敗(結束碼 %d)", res.ExitCode)
			}
			changed, ok := idempotencyChangedCount(res.Stdout)
			if !ok {
				return fmt.Errorf("冪等性檢查無 PLAY RECAP，無法確認 changed=0")
			}
			if changed != 0 {
				return fmt.Errorf("冪等性檢查失敗：第二次套用仍有 %d 個變更", changed)
			}
			fmt.Fprintln(out, "✓ 冪等性檢查通過 (changed=0)")
			return nil
		}
	}
	txn := delivery.Transaction{
		Preflight: options.Preflight, Preview: preview, Apply: apply, Verify: options.Verify,
		Idempotency: idempotency, Rollback: options.Rollback,
		Stage: options.Stage, IdempotencyPolicy: options.Idempotency, RollbackPolicy: options.RollbackPolicy,
	}
	if options.Writer != nil {
		txn.Writer = options.Writer
	}
	outcome, err := txn.Run(ctx)
	if errors.Is(err, delivery.ErrCancelled) {
		return errDeployAborted
	}
	if err != nil {
		return fmt.Errorf("delivery transaction %s: %w", outcome, err)
	}
	return nil
}

// executeRecordedDeployment starts the append-only run before transaction
// preflight. Its evidence scope is the exact contract role/limit selected for
// apply, not every host that happens to exist in the inventory.
func executeRecordedDeployment(ctx context.Context, runner *ansible.Runner, out io.Writer, playbook, inv, limit, tags string, extraVars []string, vault vaultInput, stage string, componentHints []string) error {
	root, err := resolveContractRoot("")
	if err != nil {
		return err
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		return err
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return fmt.Errorf("load contract catalog before deployment: %w", err)
	}
	components, err := componentsForPlaybook(catalog, playbook, tags, componentHints)
	if err != nil {
		return err
	}
	applied, selected, scope, hosts, err := resolveDeploymentScope(ctx, catalog, components, inv, limit, extraVars, playbook == "playbooks/site.yml")
	if err != nil {
		return err
	}
	components = contractIDs(applied)
	inputs, err := resolveDeploymentInputs(ctx, selected, scope, inv, extraVars, vault)
	if err != nil {
		return err
	}

	st, err := openSpecStore()
	if err != nil {
		return fmt.Errorf("open deployment evidence store: %w", err)
	}
	writer, err := store.StartRun(ctx, st, store.RunStarted{
		Stage: stage, Component: components[0], Components: components, Playbook: playbook,
		Inventory: inv, Hosts: hosts, Metadata: deploymentMetadata(extraVars, vault, tags),
	})
	if err != nil {
		_ = st.Close()
		return fmt.Errorf("start deployment evidence run: %w", err)
	}
	writer.StartHeartbeat(ctx, 10*time.Second)
	fmt.Fprintf(out, "ℹ️  deployment run: %s\n", writer.RunID())

	preflight := func(context.Context) error {
		result, err := delivery.ValidateContractPreflight(delivery.PreflightRequest{
			Selected: selected, Scope: scope, Inputs: inputs,
		})
		for _, warning := range result.Warnings {
			fmt.Fprintf(out, "⚠️  %s\n", warning)
		}
		return err
	}
	verify, err := autoDeployVerify(root, catalog, components, inv, limit, tags, stage, writer)
	if err != nil {
		_ = writer.Finish(ctx, store.RunFinished{Outcome: string(delivery.OutcomeFailed), ExitCode: 1})
		_ = st.Close()
		return err
	}
	rollback, rollbackPolicy := deploymentRollbackStep(runner, out, applied, inv, limit, extraVars, vault)
	err = executeDeploymentTransaction(ctx, runner, out, playbook, inv, limit, tags, extraVars, vault, deploymentTransactionOptions{
		Writer: writer, Preflight: preflight, Verify: verify, Rollback: rollback,
		Stage: stage, Idempotency: delivery.IdempotencyStageGTEStaging, RollbackPolicy: rollbackPolicy,
	})
	closeErr := st.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func componentsForPlaybook(catalog contract.Catalog, playbook, requestedTags string, hints []string) ([]string, error) {
	if len(hints) > 0 {
		components := append([]string(nil), hints...)
		sort.Strings(components)
		for _, id := range components {
			component, ok := catalog.Component(id)
			if !ok {
				return nil, fmt.Errorf("deployment component %q is not in the contract catalog", id)
			}
			if component.Playbooks.Apply != playbook {
				return nil, fmt.Errorf("component %q apply playbook is %s, not %s", id, component.Playbooks.Apply, playbook)
			}
		}
		return components, nil
	}
	requested := csvSet(requestedTags)
	components := make([]string, 0)
	for _, component := range catalog.Components() {
		if playbook == "playbooks/site.yml" && component.Site.Include {
			if len(requested) > 0 && !componentMatchesTags(component, requested) {
				continue
			}
			components = append(components, component.ID)
			continue
		}
		if component.Playbooks.Apply == playbook {
			components = append(components, component.ID)
		}
	}
	sort.Strings(components)
	if len(components) == 0 {
		return nil, fmt.Errorf("deployment playbook %s and tags %q resolve no component contract", playbook, requestedTags)
	}
	return components, nil
}

func csvSet(value string) map[string]bool {
	set := make(map[string]bool)
	for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
		if item = strings.TrimSpace(item); item != "" {
			set[item] = true
		}
	}
	return set
}

func componentMatchesTags(component contract.Contract, requested map[string]bool) bool {
	if requested[component.ID] || requested[component.Role] {
		return true
	}
	for _, tag := range component.Site.Tags {
		if requested[tag] {
			return true
		}
	}
	return false
}

func resolveDeploymentScope(ctx context.Context, catalog contract.Catalog, componentIDs []string, inventory, limit string, extraVars []string, allowEmpty bool) ([]contract.Contract, []contract.Contract, delivery.Scope, []string, error) {
	targetOverride := extraVarValue(extraVars, "target_group")
	scope := delivery.Scope{HostsByRole: make(map[string][]string)}
	applied := make([]contract.Contract, 0, len(componentIDs))
	byID := make(map[string]contract.Contract)
	allHosts := make(map[string]struct{})
	inventoryGroups, err := resolveInventoryGroups(ctx, inventory)
	if err != nil {
		return nil, nil, scope, nil, err
	}

	resolve := func(component contract.Contract, override string) ([]string, error) {
		if hosts, ok := scope.HostsByRole[component.Role]; ok && override == "" {
			return hosts, nil
		}
		if override == "" && limit == "" {
			hosts := append([]string(nil), inventoryGroups[component.Role]...)
			scope.HostsByRole[component.Role] = hosts
			return hosts, nil
		}
		pattern := component.Role
		if override != "" {
			pattern = override
		}
		hosts, err := resolvePatternHosts(ctx, inventory, pattern, limit)
		if err != nil {
			return nil, fmt.Errorf("resolve component %q role %q: %w", component.ID, pattern, err)
		}
		if override == "" {
			scope.HostsByRole[component.Role] = hosts
		}
		return hosts, nil
	}

	for _, id := range componentIDs {
		component, ok := catalog.Component(id)
		if !ok {
			return nil, nil, scope, nil, fmt.Errorf("component %q is absent from contract catalog", id)
		}
		hosts, err := resolve(component, targetOverride)
		if err != nil {
			return nil, nil, scope, nil, err
		}
		if len(hosts) == 0 && allowEmpty {
			continue
		}
		if len(hosts) == 0 {
			return nil, nil, scope, nil, fmt.Errorf("component %q role %q resolves no hosts", component.ID, component.Role)
		}
		scope.HostsByRole[component.Role] = hosts
		applied = append(applied, component)
		byID[component.ID] = component
		for _, host := range hosts {
			allHosts[host] = struct{}{}
		}
	}
	if len(applied) == 0 {
		return nil, nil, scope, nil, fmt.Errorf("selected deployment resolves no active component hosts")
	}

	var addDependencies func(contract.Contract) error
	addDependencies = func(component contract.Contract) error {
		for _, dependency := range component.Dependencies {
			if !dependency.Required {
				continue
			}
			if _, present := byID[dependency.Component]; present {
				continue
			}
			provider, ok := catalog.Component(dependency.Component)
			if !ok {
				return fmt.Errorf("component %q dependency %q is absent from catalog", component.ID, dependency.Component)
			}
			hosts, err := resolve(provider, "")
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return fmt.Errorf("component %q requires dependency %q but role %q resolves no hosts", component.ID, provider.ID, provider.Role)
			}
			byID[provider.ID] = provider
			if err := addDependencies(provider); err != nil {
				return err
			}
		}
		return nil
	}
	for _, component := range applied {
		if err := addDependencies(component); err != nil {
			return nil, nil, scope, nil, err
		}
	}

	selected := make([]contract.Contract, 0, len(byID))
	for _, component := range byID {
		selected = append(selected, component)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	hosts := make([]string, 0, len(allHosts))
	for host := range allHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return applied, selected, scope, hosts, nil
}

func resolveInventoryGroups(ctx context.Context, inventory string) (map[string][]string, error) {
	command := exec.CommandContext(ctx, "ansible-inventory", "-i", inventory, "--list")
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("ansible-inventory --list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var raw map[string]struct {
		Hosts    []string `json:"hosts"`
		Children []string `json:"children"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &raw); err != nil {
		return nil, fmt.Errorf("parse ansible-inventory output: %w", err)
	}
	resolved := make(map[string][]string, len(raw))
	visiting := make(map[string]bool)
	var expand func(string) ([]string, error)
	expand = func(group string) ([]string, error) {
		if hosts, ok := resolved[group]; ok {
			return hosts, nil
		}
		if visiting[group] {
			return nil, fmt.Errorf("inventory group cycle at %q", group)
		}
		visiting[group] = true
		set := make(map[string]struct{})
		entry := raw[group]
		for _, host := range entry.Hosts {
			set[host] = struct{}{}
		}
		for _, child := range entry.Children {
			hosts, err := expand(child)
			if err != nil {
				return nil, err
			}
			for _, host := range hosts {
				set[host] = struct{}{}
			}
		}
		delete(visiting, group)
		hosts := make([]string, 0, len(set))
		for host := range set {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		resolved[group] = hosts
		return hosts, nil
	}
	for group := range raw {
		if group == "_meta" {
			continue
		}
		if _, err := expand(group); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

func resolvePatternHosts(ctx context.Context, inventory, pattern, limit string) ([]string, error) {
	args := []string{pattern, "-i", inventory, "--list-hosts"}
	if limit != "" {
		args = append(args, "--limit", limit)
	}
	command := exec.CommandContext(ctx, "ansible", args...)
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("ansible %s --list-hosts: %w: %s", pattern, err, strings.TrimSpace(stderr.String()))
	}
	hosts := make([]string, 0)
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "hosts (") {
			continue
		}
		hosts = append(hosts, line)
	}
	sort.Strings(hosts)
	return hosts, nil
}

func extraVarValue(extraVars []string, wanted string) string {
	for i := len(extraVars) - 1; i >= 0; i-- {
		key, value, ok := strings.Cut(extraVars[i], "=")
		if ok && key == wanted {
			return value
		}
	}
	return ""
}

func resolveDeploymentInputs(ctx context.Context, selected []contract.Contract, scope delivery.Scope, inventory string, extraVars []string, vault vaultInput) (map[string]map[string]any, error) {
	values := make(map[string]any)
	hostVars, err := resolveInventoryVariables(ctx, inventory, extraVars, vault)
	if err != nil {
		return nil, err
	}
	for _, raw := range extraVars {
		key, value, ok := strings.Cut(raw, "=")
		if !ok || key == "" {
			continue
		}
		var typed any
		if err := yaml.Unmarshal([]byte(value), &typed); err != nil {
			return nil, fmt.Errorf("decode extra var %q: %w", key, err)
		}
		values[key] = typed
	}
	resolved := make(map[string]map[string]any, len(selected))
	for _, component := range selected {
		componentValues := make(map[string]any)
		for _, input := range component.GroupVars {
			if value, ok := values[input.Name]; ok {
				componentValues[input.Name] = value
				continue
			}
			for _, host := range scope.HostsByRole[component.Role] {
				if value, ok := hostVars[host][input.Name]; ok {
					componentValues[input.Name] = value
					break
				}
			}
		}
		resolved[component.ID] = componentValues
	}
	return resolved, nil
}

func resolveInventoryVariables(ctx context.Context, inventory string, extraVars []string, vault vaultInput) (map[string]map[string]any, error) {
	args := []string{"-i", inventory, "--list"}
	for _, value := range extraVars {
		args = append(args, "-e", value)
	}
	args = append(args, vault.args()...)
	command := exec.CommandContext(ctx, "ansible-inventory", args...)
	command.Stdin = os.Stdin
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("resolve inventory variables: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var raw struct {
		Meta struct {
			Hostvars map[string]map[string]any `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &raw); err != nil {
		return nil, fmt.Errorf("parse inventory variables: %w", err)
	}
	if raw.Meta.Hostvars == nil {
		raw.Meta.Hostvars = make(map[string]map[string]any)
	}
	return raw.Meta.Hostvars, nil
}

func deploymentRollbackStep(runner *ansible.Runner, out io.Writer, selected []contract.Contract, inventory, limit string, extraVars []string, vault vaultInput) (delivery.StepFunc, delivery.RollbackPolicy) {
	rollbackPlaybooks := make([]string, 0)
	for i := len(selected) - 1; i >= 0; i-- {
		if selected[i].Playbooks.Rollback != nil {
			rollbackPlaybooks = append(rollbackPlaybooks, *selected[i].Playbooks.Rollback)
		}
	}
	if len(rollbackPlaybooks) == 0 {
		return nil, delivery.RollbackNone
	}
	return func(ctx context.Context) error {
		for _, playbook := range rollbackPlaybooks {
			args := []string{playbook, "-i", inventory}
			if limit != "" {
				args = append(args, "--limit", limit)
			}
			for _, value := range extraVars {
				args = append(args, "-e", value)
			}
			args = append(args, vault.args()...)
			fmt.Fprintf(out, "▶ 回滾：ansible-playbook %s\n", strings.Join(args, " "))
			result, err := runner.Run(ctx, args...)
			if err != nil {
				return err
			}
			if result.ExitCode != 0 {
				return fmt.Errorf("rollback playbook %s failed with exit code %d", playbook, result.ExitCode)
			}
		}
		return nil
	}, delivery.RollbackPlaybook
}

func contractIDs(contracts []contract.Contract) []string {
	ids := make([]string, 0, len(contracts))
	for _, component := range contracts {
		ids = append(ids, component.ID)
	}
	sort.Strings(ids)
	return ids
}

func deploymentMetadata(extraVars []string, vault vaultInput, tags string) map[string]any {
	keys := make([]string, 0, len(extraVars))
	for _, extra := range extraVars {
		key, _, found := strings.Cut(extra, "=")
		if found && key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	metadata := map[string]any{"extra_var_keys": keys, "tags": tags, "authorization": "interactive-stage-confirmed"}
	if vault.ExtraVarsFile != "" {
		metadata["vault_reference"] = filepath.Base(vault.ExtraVarsFile)
	}
	if vault.AskVaultPass {
		metadata["vault_password_prompted"] = true
	}
	return metadata
}

func resolveInventoryHosts(ctx context.Context, inventory string) ([]string, error) {
	command := exec.CommandContext(ctx, "ansible-inventory", "-i", inventory, "--list")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("ansible-inventory --list: %w", err)
	}
	var raw struct {
		Meta struct {
			Hostvars map[string]json.RawMessage `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("parse ansible-inventory output: %w", err)
	}
	hosts := make([]string, 0, len(raw.Meta.Hostvars))
	for host := range raw.Meta.Hostvars {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("inventory resolved no hosts")
	}
	return hosts, nil
}

func autoDeployVerify(root string, catalog contract.Catalog, components []string, inventory, limit, tags, stage string, writer *store.RunWriter) (delivery.StepFunc, error) {
	auto := make([]string, 0, len(components))
	for _, id := range components {
		component, ok := catalog.Component(id)
		if !ok {
			return nil, fmt.Errorf("selected component %q disappeared from contract catalog", id)
		}
		if component.Verification.AutoDeploy != nil && *component.Verification.AutoDeploy {
			auto = append(auto, id)
		}
	}
	if len(auto) == 0 {
		return nil, nil
	}
	plans, err := delivery.PlanVerification(root, catalog, auto)
	if err != nil {
		return nil, err
	}
	plans, err = scopeVerificationPlans(catalog, plans, tags)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		selectedComponents := make(map[string]bool, len(components))
		for _, id := range components {
			selectedComponents[id] = true
		}
		for _, plan := range plans {
			selectedRows := make(map[string]bool, len(plan.Rows))
			for _, row := range plan.Rows {
				selectedRows[row.ID] = true
			}
			tool := &tools.VerifySpecTool{
				Inventory: inventory, Limit: limit, Host: plan.Role, EvidenceWriter: writer,
				Stage: stage, SelectedComponents: selectedComponents, SelectedRowIDs: selectedRows,
			}
			result, err := tool.Execute(ctx, json.RawMessage(fmt.Sprintf(`{"spec_path":%q}`, filepath.Join(root, plan.SpecPath))))
			if err != nil {
				return fmt.Errorf("execute auto verification %s: %w", plan.SpecPath, err)
			}
			if result.IsError {
				return fmt.Errorf("auto verification %s: %s", plan.SpecPath, strings.TrimSpace(result.Content))
			}
			rows, err := tools.ReadNDJSON(result.Content)
			if err != nil {
				return fmt.Errorf("decode auto verification %s: %w", plan.SpecPath, err)
			}
			for _, row := range rows {
				if row.Status == "fail" {
					return fmt.Errorf("auto verification %s %s on %s failed: %s", plan.SpecPath, row.ID, row.Host, row.Detail)
				}
			}
		}
		return nil
	}, nil
}

func scopeVerificationPlans(catalog contract.Catalog, plans []delivery.VerificationPlan, requestedTags string) ([]delivery.VerificationPlan, error) {
	requested := csvSet(requestedTags)
	if len(requested) == 0 {
		return plans, nil
	}
	if requested["never"] {
		return nil, fmt.Errorf("--tags never cannot produce a verifiable deployment scope")
	}
	known := map[string]bool{"always": true}
	selected := make([]delivery.VerificationPlan, 0, len(plans))
	for _, plan := range plans {
		component, ok := catalog.Component(plan.Component)
		if !ok {
			return nil, fmt.Errorf("verification plan component %q disappeared", plan.Component)
		}
		coarse := map[string]bool{component.ID: true, component.Role: true}
		for _, tag := range component.Site.Tags {
			coarse[tag] = true
		}
		for tag := range coarse {
			known[tag] = true
		}
		allRows := false
		for tag := range requested {
			if coarse[tag] {
				allRows = true
			}
		}
		rows := make([]spec.Row, 0, len(plan.Rows))
		for _, row := range plan.Rows {
			rowTags, err := contractRowTags(component, plan.SpecPath, row.ID)
			if err != nil {
				return nil, err
			}
			matched := allRows
			for _, tag := range rowTags {
				known[tag] = true
				if requested[tag] {
					matched = true
				}
			}
			if matched {
				rows = append(rows, row)
			}
		}
		if len(rows) > 0 {
			plan.Rows = rows
			selected = append(selected, plan)
		}
	}
	for tag := range requested {
		if !known[tag] {
			return nil, fmt.Errorf("--tags %q cannot be mapped unambiguously to contract verification rows", tag)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("--tags %q selected no auto-deploy verification rows", requestedTags)
	}
	return selected, nil
}

func contractRowTags(component contract.Contract, specPath, rowID string) ([]string, error) {
	ref := specPath + "#" + rowID
	switch component.Traceability.Mode {
	case "rowTags":
		if exemption, ok := component.Traceability.Exemptions[ref]; ok {
			return append([]string(nil), exemption.Tags...), nil
		}
		if component.Traceability.Tag == nil {
			return nil, fmt.Errorf("component %q rowTags traceability has no strategy", component.ID)
		}
		switch component.Traceability.Tag.Kind {
		case "bare":
			return []string{rowID}, nil
		case "rolePrefixed":
			return []string{component.Traceability.Tag.Prefix + "-" + rowID}, nil
		default:
			return nil, fmt.Errorf("component %q has unsupported row tag strategy %q", component.ID, component.Traceability.Tag.Kind)
		}
	case "mapped":
		if trace, ok := component.Traceability.Rows[ref]; ok {
			return append([]string(nil), trace.Tags...), nil
		}
		if exemption, ok := component.Traceability.Exemptions[ref]; ok {
			return append([]string(nil), exemption.Tags...), nil
		}
		return nil, fmt.Errorf("component %q row %s has no traceability mapping", component.ID, ref)
	default:
		return nil, fmt.Errorf("component %q has unsupported traceability mode %q", component.ID, component.Traceability.Mode)
	}
}

// ---- full-site flow ---------------------------------------------------------

func runSiteDeploy(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string) error {
	fmt.Fprintln(out, "全站部署會套用 inventory 裡每一個已經填了機器的角色 group；")
	fmt.Fprintln(out, "沒填機器的角色會自動跳過，不需要為它們準備 group_vars/vault。")
	fmt.Fprintln(out)

	decision, err := promptStageDecision(out, "site.yml")
	if err != nil {
		return err
	}
	// site.yml aggregates every apply playbook; most read `stage`,
	// os-patch-sla reads `patch_stage` — set both so one answer here
	// covers every component (see AGENTS.md §4.3 / os-patch-sla note).
	extraVars := []string{"stage=" + decision.Stage, "patch_stage=" + decision.Stage}
	extraVars = append(extraVars, decision.ConfirmVars...)

	limit, err := runTextProgram("要限定只套用到某台主機嗎？(--limit，留空 = 不限定)", "", nil)
	if err != nil {
		return err
	}
	tags, err := runTextProgram("要只跑某幾類元件嗎？(--tags，例如 freeipa,keycloak；留空 = 全部)", "", validateOptionalKV)
	if err != nil {
		return err
	}

	vault, err := promptVault(out, inv, "只有你的 inventory 實際填了 freeipa-server/keycloak/keycloak-db 機器時才需要")
	if err != nil {
		return err
	}

	// Cross-role host addresses (thanos_s3_target_host, siem_forward_host,
	// wazuh_manager_host, …): auto-detect from the inventory exactly like the
	// single-component flow. Only vars whose source group actually resolves
	// are offered — a role group with no hosts is skipped by site.yml anyway,
	// and its consumers fall back to their own default/gate behavior.
	for _, av := range siteAutoHostVars() {
		host, ok := resolveGroupHost(ctx, inv, av.Group)
		if !ok {
			continue
		}
		q := fmt.Sprintf("偵測到這份 inventory 的 %s：%s，這次要用它嗎？(-e %s=%s)", av.Label, host, av.Var, host)
		if runConfirmProgram(q, true) {
			extraVars = append(extraVars, av.Var+"="+host)
		}
	}

	extra, err := runTextProgram("還有其他 -e 變數要帶嗎？(格式 key=value，可空白分隔多個；留空 = 沒有)", "", validateOptionalKV)
	if err != nil {
		return err
	}
	extraVars = append(extraVars, strings.Fields(extra)...)

	return executeRecordedDeployment(ctx, runner, out, "playbooks/site.yml", inv, limit, tags, extraVars, vault, decision.Stage, nil)
}

// ---- single-playbook flow ---------------------------------------------------

func runSinglePlaybookDeploy(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string) error {
	if deployActionFlag != "apply" && deployActionFlag != "upgrade" && deployActionFlag != "decommission" {
		return fmt.Errorf("--action must be apply, upgrade, or decommission")
	}
	root, err := resolveContractRoot("")
	if err != nil {
		return err
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		return err
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return err
	}
	labels := make([]string, len(deployCatalog))
	for i, p := range deployCatalog {
		labels[i] = deployMenuLabel(p, catalog)
	}
	idx, err := runSelectProgram("挑一個要佈署的元件 (contract 驅動)", labels)
	if err != nil {
		return err
	}
	entry := deployCatalog[idx]

	if entry.Note != "" {
		fmt.Fprintf(out, "ℹ️  %s\n", entry.Note)
	}

	var extraVars []string
	componentHints := []string{entry.Key}
	if len(entry.InfraRoles) > 0 {
		roleIdx, err := runSelectProgram("選擇角色(infra_role)", entry.InfraRoles)
		if err != nil {
			return err
		}
		role := entry.InfraRoles[roleIdx]
		extraVars = append(extraVars, "infra_role="+role)
		componentHints = []string{role}
	}
	if err := showContractActionPlan(out, catalog, componentHints, deployActionFlag); err != nil {
		return err
	}
	if deployActionFlag != "apply" {
		return fmt.Errorf("selected contract action %q is declared but no interactive execution adapter is available; use its reviewed playbook through the approved day-2 procedure", deployActionFlag)
	}

	defaultGroup := entry.DefaultGroup
	switch {
	case defaultGroup != "":
		// use as-is
	case len(entry.InfraRoles) > 0:
		defaultGroup = "(跟 infra_role 相同)"
	default:
		defaultGroup = "(見上方提示)"
	}
	targetGroup, err := runTextProgram(
		fmt.Sprintf("要限定只套用到哪個 group/host 嗎？(-e target_group=...；留空 = 用預設 group %q；可用交集語法如 'dns:&prod')", defaultGroup),
		"", nil,
	)
	if err != nil {
		return err
	}
	if targetGroup != "" {
		extraVars = append(extraVars, "target_group="+targetGroup)
	}

	decision, err := promptStageDecision(out, entry.Label)
	if err != nil {
		return err
	}
	extraVars = append(extraVars, entry.StageVar+"="+decision.Stage)
	extraVars = append(extraVars, decision.ConfirmVars...)

	if entry.PromptS3Config {
		s3Vars, err := promptSeaweedfsS3Config(out, decision.Stage)
		if err != nil {
			return err
		}
		extraVars = append(extraVars, s3Vars...)
	}

	for _, av := range entry.AutoHostVars {
		hostVars, err := promptAutoHostVar(ctx, out, inv, av)
		if err != nil {
			return err
		}
		extraVars = append(extraVars, hostVars...)
	}

	limit, err := runTextProgram("要限定只套用到某台主機嗎？(--limit，留空 = 不限定)", "", nil)
	if err != nil {
		return err
	}
	tags, err := runTextProgram("要只跑某幾個檢查項目嗎？(--tags，例如 C1,C2；留空 = 全部)", "", validateOptionalKV)
	if err != nil {
		return err
	}

	vault, err := promptVault(out, inv, entry.VaultHint)
	if err != nil {
		return err
	}

	extra, err := runTextProgram("還有其他 -e 變數要帶嗎？(格式 key=value，可空白分隔多個；留空 = 沒有)", "", validateOptionalKV)
	if err != nil {
		return err
	}
	extraVars = append(extraVars, strings.Fields(extra)...)

	return executeRecordedDeployment(ctx, runner, out, entry.Playbook, inv, limit, tags, extraVars, vault, decision.Stage, componentHints)
}

// deployMenuLabel keeps catalog-only copywriting as a presentation projection,
// while contract id and role remain the source of truth for what is selected.
func deployMenuLabel(entry deployPlaybook, catalog contract.Catalog) string {
	ids := entryComponentIDs(entry)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		component, ok := catalog.Component(id)
		if !ok {
			continue
		}
		parts = append(parts, component.ID+" (role="+component.Role+")")
	}
	if len(parts) == 0 {
		return entry.Label
	}
	return entry.Label + " — " + strings.Join(parts, ", ")
}

func entryComponentIDs(entry deployPlaybook) []string {
	if len(entry.InfraRoles) > 0 {
		return append([]string(nil), entry.InfraRoles...)
	}
	return []string{entry.Key}
}

// showContractActionPlan exposes the contract dependency graph and lifecycle
// availability before the wizard asks for secrets or authorizes a mutation.
func showContractActionPlan(out io.Writer, catalog contract.Catalog, ids []string, action string) error {
	for _, id := range ids {
		component, ok := catalog.Component(id)
		if !ok {
			return fmt.Errorf("deploy catalog component %q has no contract", id)
		}
		var playbook *string
		switch action {
		case "apply":
			playbook = &component.Playbooks.Apply
		case "upgrade":
			playbook = component.Playbooks.Upgrade
		case "decommission":
			playbook = component.Playbooks.Decommission
		}
		if playbook == nil || strings.TrimSpace(*playbook) == "" {
			return fmt.Errorf("component %q does not declare a %s playbook", component.ID, action)
		}
		dependencies := make([]string, 0, len(component.Dependencies))
		for _, dependency := range component.Dependencies {
			if dependency.Required {
				dependencies = append(dependencies, dependency.Component+" ("+dependency.Relation+")")
			}
		}
		sort.Strings(dependencies)
		fmt.Fprintf(out, "\nContract plan: %s\n  action: %s\n  playbook: %s\n", component.ID, action, *playbook)
		if len(dependencies) == 0 {
			fmt.Fprintln(out, "  required dependencies: none")
		} else {
			fmt.Fprintf(out, "  required dependencies: %s\n", strings.Join(dependencies, ", "))
		}
	}
	return nil
}
