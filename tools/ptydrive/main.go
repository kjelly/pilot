// ptydrive is temporary scaffolding to drive pilot's promptui/bubbletea
// wizards (`pilot edit`, `pilot deploy`) end-to-end under a real PTY, the
// way a human at a keyboard would, instead of bypassing them. Not part of
// the pilot deliverable — deleted once the demo scenario is built.
//
// Every run is recorded in the standard `script`(1) timing format
// (a "typescript" raw-output file + a "timing" file of "<delay> <bytes>"
// lines), so anyone can independently verify what actually happened by
// replaying it at real speed with the standard, preinstalled tool:
//
//	scriptreplay -t recording.timing recording.typescript
//	scriptreplay -t recording.timing recording.typescript -s 3   # 3x faster
//
// Usage:
//
//	ptydrive -script steps.txt -timeout 180 -rec recording -- /path/to/pilot edit --dir demo
//
// (-rec recording writes recording.typescript + recording.timing)
//
// Script format, one instruction per line:
//
//	# comment
//	TEXT literal text typed character-by-character (no trailing Enter)
//	ENTER
//	DOWN [n]
//	UP [n]
//	SPACE
//	TAB
//	CTRLC
//	BACKSPACE [n]   send DEL (127) — clears a promptui.Prompt's pre-filled
//	                Default text (AllowEdit puts the cursor at its end, so
//	                plain typing appends instead of replacing)
//	WAIT ms
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/creack/pty"
)

const keyDelay = 300 * time.Millisecond
const settleDelay = 700 * time.Millisecond

func main() {
	scriptPath := flag.String("script", "", "path to keystroke script")
	timeoutSec := flag.Int("timeout", 120, "overall timeout in seconds")
	logPath := flag.String("log", "", "path to write full PTY transcript (plain, no timing)")
	recBase := flag.String("rec", "", "base path for a script(1)-format recording: writes <rec>.typescript + <rec>.timing, replayable with `scriptreplay -t <rec>.timing <rec>.typescript`")
	flag.Parse()

	rest := flag.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ptydrive -script steps.txt [-timeout 120] [-log t.log] [-rec recording] -- <bin> [args...]")
		os.Exit(2)
	}
	if *scriptPath == "" {
		fmt.Fprintln(os.Stderr, "ptydrive: -script is required")
		os.Exit(2)
	}

	steps, err := loadScript(*scriptPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ptydrive: load script: %v\n", err)
		os.Exit(2)
	}

	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "CI=1")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 220})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ptydrive: pty start: %v\n", err)
		os.Exit(1)
	}
	defer ptmx.Close()

	var logf *os.File
	if *logPath != "" {
		logf, err = os.Create(*logPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptydrive: create log: %v\n", err)
			os.Exit(1)
		}
		defer logf.Close()
	}

	var rec *recorder
	if *recBase != "" {
		rec, err = newRecorder(*recBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptydrive: create recording: %v\n", err)
			os.Exit(1)
		}
		defer rec.Close()
	}

	done := make(chan struct{})
	go func() {
		writers := []io.Writer{os.Stdout}
		if logf != nil {
			writers = append(writers, logf)
		}
		if rec != nil {
			writers = append(writers, rec)
		}
		w := io.MultiWriter(writers...)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		close(done)
	}()

	// Give the process a moment to render its first prompt before we
	// start typing — matches the pacing lesson from
	// edit_role_checklist_pty_test.go: real keypress cadence, not a burst.
	time.Sleep(500 * time.Millisecond)

	for _, st := range steps {
		if err := st.apply(ptmx); err != nil {
			fmt.Fprintf(os.Stderr, "ptydrive: step %+v: %v\n", st, err)
			break
		}
	}

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	failed := false
	select {
	case err := <-exitCh:
		<-done
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptydrive: process exited: %v\n", err)
			failed = true
		} else {
			fmt.Fprintln(os.Stderr, "ptydrive: process exited 0")
		}
	case <-time.After(time.Duration(*timeoutSec) * time.Second):
		fmt.Fprintln(os.Stderr, "ptydrive: TIMEOUT — killing process")
		_ = cmd.Process.Kill()
		<-done
		failed = true
	}

	if rec != nil {
		rec.Close()
		fmt.Fprintf(os.Stderr, "ptydrive: recorded — replay with: scriptreplay -t %s.timing %s.typescript\n", *recBase, *recBase)
	}
	if logf != nil {
		logf.Close()
	}
	if failed {
		os.Exit(1)
	}
}

type step struct {
	kind string // text, enter, down, up, space, tab, ctrlc, wait
	text string
	n    int
}

func (s step) apply(w io.Writer) error {
	switch s.kind {
	case "text":
		for _, r := range s.text {
			if _, err := w.Write([]byte(string(r))); err != nil {
				return err
			}
			time.Sleep(keyDelay)
		}
	case "enter":
		if _, err := w.Write([]byte("\r")); err != nil {
			return err
		}
		// Enter always causes a prompt TRANSITION (submits the current
		// promptui.Select/Prompt and renders the next one) — that
		// render + the next prompt's readline setup is where a
		// following key send can race ahead of the process actually
		// being ready to consume it. Steady same-prompt navigation
		// (repeated arrow presses) doesn't need this; only the
		// transition does.
		time.Sleep(settleDelay)
	case "down":
		for i := 0; i < max1(s.n); i++ {
			if _, err := w.Write([]byte("\x1b[B")); err != nil {
				return err
			}
			time.Sleep(keyDelay)
		}
	case "up":
		for i := 0; i < max1(s.n); i++ {
			if _, err := w.Write([]byte("\x1b[A")); err != nil {
				return err
			}
			time.Sleep(keyDelay)
		}
	case "space":
		if _, err := w.Write([]byte(" ")); err != nil {
			return err
		}
		time.Sleep(keyDelay)
	case "tab":
		if _, err := w.Write([]byte("\t")); err != nil {
			return err
		}
		time.Sleep(keyDelay)
	case "ctrlc":
		if _, err := w.Write([]byte{0x03}); err != nil {
			return err
		}
		time.Sleep(keyDelay)
	case "backspace":
		// promptui's readline (chzyer/readline) uses DEL (127) as its
		// backspace char (CharBackspace) — needed to clear a
		// promptui.Prompt's pre-filled Default text (AllowEdit:true
		// puts the cursor at the end of it, so plain typing appends
		// rather than replaces).
		for i := 0; i < max1(s.n); i++ {
			if _, err := w.Write([]byte{127}); err != nil {
				return err
			}
			time.Sleep(keyDelay)
		}
	case "wait":
		time.Sleep(time.Duration(s.n) * time.Millisecond)
	}
	return nil
}

func max1(n int) int {
	if n <= 0 {
		return 1
	}
	return n
}

func loadScript(path string) ([]step, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var steps []step
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.SplitN(trimmed, " ", 2)
		op := strings.ToUpper(fields[0])
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}
		switch op {
		case "TEXT":
			steps = append(steps, step{kind: "text", text: arg})
		case "ENTER":
			steps = append(steps, step{kind: "enter"})
		case "DOWN":
			steps = append(steps, step{kind: "down", n: atoiOr1(arg)})
		case "UP":
			steps = append(steps, step{kind: "up", n: atoiOr1(arg)})
		case "SPACE":
			steps = append(steps, step{kind: "space"})
		case "TAB":
			steps = append(steps, step{kind: "tab"})
		case "CTRLC":
			steps = append(steps, step{kind: "ctrlc"})
		case "BACKSPACE":
			steps = append(steps, step{kind: "backspace", n: atoiOr1(arg)})
		case "WAIT":
			steps = append(steps, step{kind: "wait", n: atoiOr1(arg)})
		default:
			return nil, fmt.Errorf("unknown op %q", op)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return steps, nil
}

// recorder writes a script(1)-format recording: raw PTY output bytes go
// into <base>.typescript, and a <base>.timing file of "<delay_seconds>
// <byte_count>" lines (one per Write call) records how long to wait
// before replaying each chunk — the exact format `scriptreplay` expects,
// so anyone can watch the real driven session play back afterward
// instead of trusting a summary of what ptydrive claims it did.
type recorder struct {
	typescript *os.File
	timing     *os.File
	last       time.Time
}

func newRecorder(base string) (*recorder, error) {
	ts, err := os.Create(base + ".typescript")
	if err != nil {
		return nil, err
	}
	tm, err := os.Create(base + ".timing")
	if err != nil {
		ts.Close()
		return nil, err
	}
	return &recorder{typescript: ts, timing: tm, last: time.Now()}, nil
}

func (r *recorder) Write(p []byte) (int, error) {
	now := time.Now()
	delay := now.Sub(r.last).Seconds()
	r.last = now
	if _, err := fmt.Fprintf(r.timing, "%.6f %d\n", delay, len(p)); err != nil {
		return 0, err
	}
	return r.typescript.Write(p)
}

func (r *recorder) Close() {
	_ = r.typescript.Close()
	_ = r.timing.Close()
}

func atoiOr1(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 1
	}
	return n
}
