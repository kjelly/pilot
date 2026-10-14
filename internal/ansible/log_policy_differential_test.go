package ansible

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The tests below compare log maintenance with main before incremental
// redaction (6427b66, the base of PR #71): a full pass over the whole log on
// every maintenance, with main's code copied here unchanged. Whatever that
// masks must be masked here too, however the log is written in pieces,
// whenever maintenance runs between them, and whether or not a writer keeps
// the log open across maintenance and rotation (PR #71 reviews).
//
// The generated logs put secret values only where main masks them by its
// rules: values of sensitive keys and flags, and lines of keys that have an
// END marker. They never rely on main masking every line after a BEGIN
// marker that has no END marker: that is the one case where this package
// masks less on purpose (a new Ansible record ends such a key), so it is
// left out of the comparison rather than copied into the reference.
//
// main's rules, copied unchanged.
var (
	mainSensitiveAssignment = regexp.MustCompile(`(?i)((?:["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|vault[_-]?password|authorization)[A-Za-z0-9_.-]*["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}\]]+))`)
	mainSensitiveFlag       = regexp.MustCompile(`(?i)(--(?:password|passwd|passphrase|secret|token|api[-_]key|access[-_]key|private[-_]key|vault[-_]password)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)`)
	mainPrivateKeyBegin     = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	mainPrivateKeyEnd       = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

func mainRedactSecrets(line string) string {
	line = mainSensitiveAssignment.ReplaceAllStringFunc(line, func(match string) string {
		separator := strings.IndexAny(match, ":=")
		if separator < 0 {
			return "[REDACTED]"
		}
		return match[:separator+1] + " [REDACTED]"
	})
	return mainSensitiveFlag.ReplaceAllString(line, "$1[REDACTED]")
}

// mainFullPass is main's redactFile on a string.
func mainFullPass(content string) string {
	var out strings.Builder
	reader := bufio.NewReader(strings.NewReader(content))
	inPrivateKey := false
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			switch {
			case inPrivateKey:
				inPrivateKey = !mainPrivateKeyEnd.MatchString(line)
				out.WriteString(preserveLineEnding(line, "[REDACTED PRIVATE KEY]"))
			case mainPrivateKeyBegin.MatchString(line):
				inPrivateKey = !mainPrivateKeyEnd.MatchString(line)
				out.WriteString(preserveLineEnding(line, "[REDACTED PRIVATE KEY]"))
			default:
				out.WriteString(mainRedactSecrets(line))
			}
		}
		if err != nil {
			return out.String()
		}
	}
}

// Secret values in generated logs are made of letters that nothing else in
// them uses, so any six of them in a row in the output are part of one.
var secretValue = regexp.MustCompile(`[QZXJLMU]{12}`)

const secretLetters = "QZXJLMU"

func leaks(output, secret string) bool {
	for i := 0; i+6 <= len(secret); i++ {
		if strings.Contains(output, secret[i:i+6]) {
			return true
		}
	}
	return false
}

// checkMasksWhatMainMasks writes content in the pieces that cuts gives,
// maintains after the pieces that maintainAfter marks and once at the end,
// both here and with main's redaction, and fails for any secret value main
// masked that is left here, in part or in full.
func checkMasksWhatMainMasks(t *testing.T, content string, cuts []int, maintainAfter []bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible.log")
	var mainLog string
	start := 0
	for i := 0; i <= len(cuts); i++ {
		end := len(content)
		if i < len(cuts) {
			end = cuts[i]
		}
		piece := content[start:end]
		start = end
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(piece); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		mainLog += piece
		if i < len(maintainAfter) && maintainAfter[i] {
			maintain(t, path)
			mainLog = mainFullPass(mainLog)
		}
	}
	got := maintainTwice(t, path)
	mainLog = mainFullPass(mainLog)
	for _, secret := range secretValue.FindAllString(content, -1) {
		if !leaks(mainLog, secret) && leaks(got, secret) {
			t.Errorf("main masks %s, maintenance here leaves it\ncontent: %q\ncuts: %v, maintain after: %v\nhere: %q\nmain: %q",
				secret, content, cuts, maintainAfter, got, mainLog)
		}
	}
	// RedactSecrets is idempotent on everything it produced.
	for _, line := range strings.SplitAfter(got, "\n") {
		if again := RedactSecrets(line); again != line {
			t.Errorf("RedactSecrets changes its own output %q to %q", line, again)
		}
	}
}

// secretLog generates Ansible-like log content with secret values in the
// places the rules cover, including the cases the review found.
type secretLog struct {
	r *rand.Rand
	b strings.Builder
}

func (g *secretLog) secret() string {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteByte(secretLetters[g.r.Intn(len(secretLetters))])
	}
	return b.String()
}

func (g *secretLog) record(message string) {
	g.b.WriteString(testRecord(message))
	if g.r.Intn(10) == 0 {
		g.b.WriteString("\r")
	}
	g.b.WriteString("\n")
}

func (g *secretLog) key(indent string, body int) {
	g.b.WriteString(indent + "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for i := 0; i < body; i++ {
		g.b.WriteString(indent + g.secret() + g.secret() + "\n")
	}
	g.b.WriteString(indent + "-----END OPENSSH PRIVATE KEY-----\n")
}

// keyLoop logs a loop over a key's lines in the shapes captured from
// ansible-core 2.19.2: one record per item, with the lines that belong to
// it, and an error report between items.
func (g *secretLog) keyLoop() {
	if g.r.Intn(2) == 0 {
		g.record("TASK [loop over key lines] ***")
	}
	lines := []string{"-----BEGIN RSA PRIVATE KEY-----"}
	for n := 1 + g.r.Intn(3); n > 0; n-- {
		lines = append(lines, g.secret()+g.secret())
	}
	lines = append(lines, "-----END RSA PRIVATE KEY-----")
	shape := g.r.Intn(4)
	for i, line := range lines {
		switch shape {
		case 0:
			g.record("changed: [h] => (item=" + line + ")")
		case 1:
			g.record("ok: [h] => (item=" + line + ") => {")
			g.b.WriteString("    \"msg\": \"" + line + "\"\n}\n")
		case 2:
			if i == 1 {
				g.b.WriteString("2026-09-15 09:50:37,791 p=4242 u=pilot n=ansible ERROR| [ERROR]: Task failed: Module failed: non-zero return code\nOrigin: /x/play.yml:20:7\n\n")
			}
			g.record(`failed: [h] (item=` + line + `) => {"ansible_loop_var": "item", "changed": true, "cmd": ["false", "` + line + `"], "item": "` + line + `", "rc": 1}`)
		default:
			g.record(`changed: [h] => (item=` + line + `) => {"ansible_loop_var": "item", "changed": true, "cmd": ["echo", "` + line + `"], "stdout": "` + line + `"}`)
		}
	}
}

func (g *secretLog) piece() {
	s := g.secret
	switch g.r.Intn(20) {
	case 0, 1:
		g.record("ok: [h] => ordinary output line")
	case 2:
		g.record("password: " + s())
	case 3:
		g.record(fmt.Sprintf(`ok: [h] => {"api_key": "%s", "token": "%s", "other": 1}`, s(), s()))
	case 4:
		g.record("TASK [x] client_secret = '" + s() + "' Authorization: " + s())
	case 5:
		g.record("cmd: tool --password " + s() + " --secret=" + s() + ` --token "` + s() + `"`)
	case 6:
		g.record("password:[REDACTED]--password " + s())
	case 7:
		g.record("password: [REDACTED-" + s())
	case 8:
		g.record("password: [REDACTED] token=[REDACTED]] vault_password: " + s())
	case 9:
		g.record("ok: [h] => ")
		g.key("", 1+g.r.Intn(3))
	case 10:
		g.record("ok: [h] => ")
		g.key("    ", 1+g.r.Intn(3))
	case 11:
		g.record(`ok: [h] => {"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n` + s() + `\n` + s() + `\n-----END OPENSSH PRIVATE KEY-----\n"}`)
	case 12:
		g.record(`changed: [h] => {"cmd": "grep -q -- '-----BEGIN RSA PRIVATE KEY-----' /etc/x"}`)
	case 13:
		g.record("-----BEGIN RSA PRIVATE KEY-----")
		g.record(s() + s())
		g.record("Hw==")
		g.record("-----END RSA PRIVATE KEY-----")
	case 14:
		g.b.WriteString("    \"password\": \"" + s() + "\",\n")
	case 15:
		g.record("password=abc]def token: " + s())
	case 16:
		g.record("ok: [h] => {\"msg\": \"password: [REDACTED]\"}")
	case 17, 18:
		g.keyLoop()
	default:
		g.b.WriteString("multi-line record continuation " + s()[:3] + "\n")
	}
}

// generateSecretLog returns one log and a random way to write and
// maintain it.
func generateSecretLog(r *rand.Rand) (string, []int, []bool) {
	content, _ := generateSecretPieces(r)
	cuts := make([]int, r.Intn(7))
	for i := range cuts {
		cuts[i] = r.Intn(len(content) + 1)
	}
	sortInts(cuts)
	maintainAfter := make([]bool, len(cuts)+1)
	for i := range maintainAfter {
		maintainAfter[i] = r.Intn(10) < 7
	}
	return content, cuts, maintainAfter
}

// generateSecretPieces returns one log and the offsets where its pieces
// end. A piece is what one Ansible process writes as a whole: a record, or
// a key, or a loop over one.
func generateSecretPieces(r *rand.Rand) (string, []int) {
	g := &secretLog{r: r}
	var ends []int
	for n := 1 + r.Intn(12); n > 0; n-- {
		g.piece()
		ends = append(ends, g.b.Len())
	}
	content := g.b.String()
	if r.Intn(3) == 0 {
		content = content[:r.Intn(len(content)+1)] // a run cut short
		for i := range ends {
			ends[i] = min(ends[i], len(content))
		}
	}
	return content, ends
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func TestMaintainLogMasksWhatMainMasks(t *testing.T) {
	cases := 400
	if testing.Short() {
		cases = 50
	}
	r := rand.New(rand.NewSource(71))
	for i := 0; i < cases; i++ {
		content, cuts, maintainAfter := generateSecretLog(r)
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			checkMasksWhatMainMasks(t, content, cuts, maintainAfter)
		})
	}
}

// The review's cases, written in the pieces it gave.
func TestMaintainLogMasksWhatMainMasksInTheReviewedCases(t *testing.T) {
	flag := "password:[REDACTED]--password QZXJLMUQZXJLMU\n"
	checkMasksWhatMainMasks(t, flag, nil, nil)
	pieces := []string{
		`ok: [h] => {"private_key": "`,
		`-----BEGIN OPENSSH PRIVATE`,
		` KEY-----\nQZXJLMUQZXJLMU\n-----END OPENSSH PRIVATE KEY-----\n"}` + "\n",
	}
	content := strings.Join(pieces, "")
	checkMasksWhatMainMasks(t, content, []int{len(pieces[0]), len(pieces[0]) + len(pieces[1])}, []bool{true, true, true})
	if got := mainFullPass(content); leaks(got, "QZXJLMUQZXJLMU") {
		t.Fatalf("test setup: main does not mask the key: %q", got)
	}
}

// FuzzMaintainLogMasksWhatMainMasks explores more generated logs and ways
// to write them, picked by seed. Free-form content would put secret values
// where only main's masking of everything after a BEGIN marker without an
// END marker covers them, the case left out of the comparison.
func FuzzMaintainLogMasksWhatMainMasks(f *testing.F) {
	for seed := int64(0); seed < 8; seed++ {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		content, cuts, maintainAfter := generateSecretLog(r)
		checkMasksWhatMainMasks(t, content, cuts, maintainAfter)
		checkKeepsNothingMainWouldMask(t, generateLogSteps(r))
	})
}

// checkRedactSecretsLine checks RedactSecrets on one line against main:
// main's passes, folded, until the line stops changing (see
// RedactSecrets); unchanged when redacted again; and no secret value left
// that main masks even when it redacts the line three times, as it did at
// every maintenance.
func checkRedactSecretsLine(t *testing.T, line string) {
	t.Helper()
	once := RedactSecrets(line)
	if again := RedactSecrets(once); again != once {
		t.Errorf("RedactSecrets(%q) = %q, and again %q", line, once, again)
	}
	want := line
	for range 4 {
		next := grownMarker.ReplaceAllString(mainRedactSecrets(want), "[REDACTED]")
		if next == want {
			break
		}
		want = next
	}
	if once != want {
		t.Errorf("RedactSecrets(%q) = %q; main's passes, folded, give %q", line, once, want)
	}
	mainRepeated := mainRedactSecrets(mainRedactSecrets(mainRedactSecrets(line)))
	for _, secret := range secretValue.FindAllString(line, -1) {
		if !leaks(mainRepeated, secret) && leaks(once, secret) {
			t.Errorf("RedactSecrets(%q) = %q keeps %s; main masks it: %q", line, once, secret, mainRepeated)
		}
	}
}

var redactLineAtoms = []string{
	"password", "Password", "--password", "--secret", "--token=", "token", "api_key", "client_secret",
	"Authorization", "vault_password", ":", "=", " ", "\t", "\r", "]", "]]", "[", "[REDACTED]", "[REDACTED",
	"[redacted]", `"`, "'", ",", "}", "{", "-", "--", "x", "abc",
}

func randomRedactLine(r *rand.Rand) string {
	var b strings.Builder
	for n := 1 + r.Intn(14); n > 0; n-- {
		if r.Intn(6) == 0 {
			for i := 0; i < 12; i++ {
				b.WriteByte(secretLetters[r.Intn(len(secretLetters))])
			}
			continue
		}
		b.WriteString(redactLineAtoms[r.Intn(len(redactLineAtoms))])
	}
	return b.String()
}

// RedactSecrets on random lines made of the pieces its rules care about
// (PR #71 follow-up review: ` --password\t""]` and
// `--password=[REDACTED]--password\rSECRET` were not stable).
func TestRedactSecretsMatchesMainOnRandomLines(t *testing.T) {
	cases := 20000
	if testing.Short() {
		cases = 2000
	}
	r := rand.New(rand.NewSource(3))
	for i := 0; i < cases && !t.Failed(); i++ {
		checkRedactSecretsLine(t, randomRedactLine(r))
	}
}

func FuzzRedactSecrets(f *testing.F) {
	for _, seed := range []string{
		" --password\t\"\"]",
		"--password=[REDACTED]--password\rQZXJLMUQZXJL",
		"password:[REDACTED]--password QZXJLMUQZXJL",
		"password: [REDACTED-QZXJLMUQZXJL",
		"password=abc]def token: QZXJLMUQZXJL",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsAny(line, "\n") {
			t.Skip()
		}
		checkRedactSecretsLine(t, line)
	})
}

// logStep is one step of a run: a write, through the file the writer
// opened at the start (as Ansible keeps its log open for a whole run) or
// through a new open, or a maintenance.
type logStep struct {
	data     string
	attached bool
	maintain bool
	policy   LogPolicy
}

// checkKeepsNothingMainWouldMask runs steps, maintains once more at the
// end, and fails if the log or a retained log keeps a secret value, or part
// of one, that main masks: main's full pass at the same maintenance points
// over everything written, in the order it was written. Which bytes are
// kept at all differs from main (main detached a writer on every
// maintenance, and trims at other offsets), so only the values kept here are
// compared.
func checkKeepsNothingMainWouldMask(t *testing.T, steps []logStep) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible.log")
	writer, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var written strings.Builder
	reference := ""
	for _, step := range steps {
		switch {
		case step.maintain:
			if err := MaintainLogWithPolicy(path, step.policy); err != nil {
				t.Fatal(err)
			}
			reference = mainFullPass(reference)
		case step.attached:
			if _, err := writer.WriteString(step.data); err != nil {
				t.Fatal(err)
			}
		default:
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(step.data); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		written.WriteString(step.data)
		reference += step.data
	}
	maintain(t, path)
	reference = mainFullPass(reference)
	for name, content := range logFiles(t, path) {
		for _, secret := range secretValue.FindAllString(written.String(), -1) {
			if !leaks(reference, secret) && leaks(content, secret) {
				t.Errorf("%s keeps %s, which main masks\nsteps: %+v\nfile: %q\nmain: %q", filepath.Base(name), secret, steps, content, reference)
			}
		}
	}
}

// generateLogSteps writes a generated log as Ansible processes would: each
// piece (a record, a key, a loop over a key) by one writer, either the one
// holding the log open from the start or a new open, with maintenance
// (sometimes with rotation or truncation) between writes. The open writer
// may write a piece in two parts with maintenance between them; a piece is
// never continued by another writer.
func generateLogSteps(r *rand.Rand) []logStep {
	content, ends := generateSecretPieces(r)
	var steps []logStep
	maintenance := func() {
		policy := DefaultLogPolicy()
		if r.Intn(3) == 0 {
			policy = LogPolicy{MaxBytes: int64(64 + r.Intn(512)), MaxFiles: r.Intn(3)}
		}
		steps = append(steps, logStep{maintain: true, policy: policy})
	}
	start := 0
	for _, end := range ends {
		piece := content[start:end]
		start = end
		attached := r.Intn(2) == 0
		if attached && piece != "" && r.Intn(3) == 0 {
			cut := r.Intn(len(piece) + 1)
			steps = append(steps, logStep{data: piece[:cut], attached: true})
			maintenance()
			piece = piece[cut:]
		}
		steps = append(steps, logStep{data: piece, attached: attached})
		if r.Intn(10) < 6 {
			maintenance()
		}
	}
	return steps
}

// Logs written in pieces, partly through a writer that holds the log open
// across maintenance, with rotation and truncation in between.
func TestMaintainLogKeepsNothingMainWouldMask(t *testing.T) {
	cases := 300
	if testing.Short() {
		cases = 40
	}
	r := rand.New(rand.NewSource(7071))
	for i := 0; i < cases; i++ {
		steps := generateLogSteps(r)
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			checkKeepsNothingMainWouldMask(t, steps)
		})
	}
}
