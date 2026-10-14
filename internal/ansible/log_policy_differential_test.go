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

// The tests below compare log maintenance with the redaction main did before
// incremental redaction (main 6427b66): a full pass over the whole log on
// every maintenance. Whatever that masked must be masked here too, however
// the log is written in pieces and whenever maintenance runs between them
// (PR #71 review).
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

// mainFullPass is main's redactFile on a string. One change is made on
// purpose: like this package now, it ends a private key at the next Ansible
// record whose message cannot be key material. main kept masking every line
// up to an END marker that might never come; that is over-masking, which
// the review asked to bound, not a rule to keep.
func mainFullPass(content string) string {
	var out strings.Builder
	reader := bufio.NewReader(strings.NewReader(content))
	inPrivateKey := false
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if inPrivateKey && ansibleRecord.MatchString(line) && !ansibleKeyRecord.MatchString(line) {
				inPrivateKey = false
			}
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

func (g *secretLog) piece() {
	s := g.secret
	switch g.r.Intn(18) {
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
	default:
		g.b.WriteString("multi-line record continuation " + s()[:3] + "\n")
	}
}

// generate returns one log and a random way to write and maintain it.
func generateSecretLog(r *rand.Rand) (string, []int, []bool) {
	g := &secretLog{r: r}
	for n := 1 + r.Intn(12); n > 0; n-- {
		g.piece()
	}
	content := g.b.String()
	if r.Intn(3) == 0 {
		content = content[:r.Intn(len(content)+1)] // a run cut short
	}
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

// FuzzMaintainLogMasksWhatMainMasks explores other logs and other ways to
// write them: plan's bytes give the cut points and when maintenance runs.
func FuzzMaintainLogMasksWhatMainMasks(f *testing.F) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		content, cuts, maintainAfter := generateSecretLog(r)
		plan := make([]byte, 0, len(cuts))
		for j, cut := range cuts {
			b := byte(0)
			if len(content) > 0 {
				b = byte(cut * 255 / len(content))
			}
			if maintainAfter[j] {
				b |= 1
			} else {
				b &^= 1
			}
			plan = append(plan, b)
		}
		f.Add(content, plan)
	}
	f.Add("password:[REDACTED]--password QZXJLMUQZXJLMU\n", []byte{})
	f.Add(`ok: [h] => {"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nQZXJLMUQZXJLMU\n-----END OPENSSH PRIVATE KEY-----\n"}`+"\n", []byte{0x2f, 0x5f})
	f.Fuzz(func(t *testing.T, content string, plan []byte) {
		if len(content) > 4096 || len(plan) > 16 {
			t.Skip()
		}
		cuts := make([]int, len(plan))
		maintainAfter := make([]bool, len(plan)+1)
		for i, b := range plan {
			cuts[i] = int(b) * len(content) / 255
			maintainAfter[i] = b&1 == 1
		}
		sortInts(cuts)
		checkMasksWhatMainMasks(t, content, cuts, maintainAfter)
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
// end, and fails if the log or a retained log keeps a secret value that
// main's full pass over that file would mask: a byte that rotation or a
// still-attached writer got past the scan, or one the rules here miss.
// Which bytes are kept at all differs from main (main detaches the writer
// on every maintenance, and trims at other offsets), so this compares each
// kept file with main's rules rather than with main's files.
func checkKeepsNothingMainWouldMask(t *testing.T, steps []logStep) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible.log")
	writer, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, step := range steps {
		switch {
		case step.maintain:
			if err := MaintainLogWithPolicy(path, step.policy); err != nil {
				t.Fatal(err)
			}
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
	}
	maintain(t, path)
	for name, content := range logFiles(t, path) {
		reference := mainFullPass(content)
		for _, secret := range secretValue.FindAllString(content, -1) {
			if !leaks(reference, secret) {
				t.Errorf("%s keeps %s, which main's rules mask\nsteps: %+v\nfile: %q", filepath.Base(name), secret, steps, content)
			}
		}
	}
}

func generateLogSteps(r *rand.Rand) []logStep {
	content, cuts, maintainAfter := generateSecretLog(r)
	var steps []logStep
	start := 0
	for i := 0; i <= len(cuts); i++ {
		end := len(content)
		if i < len(cuts) {
			end = cuts[i]
		}
		steps = append(steps, logStep{data: content[start:end], attached: r.Intn(2) == 0})
		start = end
		if maintainAfter[i] {
			policy := DefaultLogPolicy()
			if r.Intn(3) == 0 {
				policy = LogPolicy{MaxBytes: int64(64 + r.Intn(512)), MaxFiles: r.Intn(3)}
			}
			steps = append(steps, logStep{maintain: true, policy: policy})
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
