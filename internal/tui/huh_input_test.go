package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestHuhInputDefaultValue(t *testing.T) {
	s := NewHuhInput(InputSpec{ScreenID: "host.name", Title: "Hostname", Default: "ipa.example.com"})
	s.Init()
	if got := s.Value(); got != "ipa.example.com" {
		t.Fatalf("Value=%q want the default", got)
	}
	st := s.AutomationState()
	if st.ScreenID != "host.name" || st.Kind != ScreenInput || st.Title != "Hostname" {
		t.Fatalf("unexpected snapshot header: %+v", st)
	}
	if !st.HasValue {
		t.Fatalf("HasValue=false with a default present")
	}
	if st.Secret {
		t.Fatalf("Secret=true on a plain input")
	}
	if st.FocusedIndex != -1 {
		t.Fatalf("FocusedIndex=%d want -1 for an input screen", st.FocusedIndex)
	}
	if !strings.Contains(s.View().Content, "ipa.example.com") {
		t.Fatalf("default not rendered")
	}

	send(t, s, keyEnter)
	if !s.Finished() || s.Canceled() {
		t.Fatalf("finished=%v canceled=%v", s.Finished(), s.Canceled())
	}
	if got := s.Value(); got != "ipa.example.com" {
		t.Fatalf("Value=%q after enter", got)
	}
}

func TestHuhInputReplaceValue(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Realm", Default: "OLD"})
	s.Init()
	for range "OLD" {
		send(t, s, keyBackspce)
	}
	if got := s.Value(); got != "" {
		t.Fatalf("Value=%q after clearing", got)
	}
	if s.AutomationState().HasValue {
		t.Fatalf("HasValue=true on an emptied input")
	}
	typeText(t, s, "EXAMPLE.COM")
	send(t, s, keyEnter)
	if got := s.Value(); got != "EXAMPLE.COM" {
		t.Fatalf("Value=%q want EXAMPLE.COM", got)
	}
}

// huh itself does not trim; Value() does, matching textInputModel so
// every edit-menu field stores a clean value.
func TestHuhInputTrimsSurroundingWhitespace(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Path"})
	s.Init()
	typeText(t, s, "   /srv/data   ")
	if got := s.Value(); got != "/srv/data" {
		t.Fatalf("Value=%q want the trimmed %q", got, "/srv/data")
	}
	send(t, s, keyEnter)
	if !s.Finished() {
		t.Fatalf("enter did not finish the screen")
	}
	if got := s.Value(); got != "/srv/data" {
		t.Fatalf("Value=%q after enter", got)
	}
}

func TestHuhInputWhitespaceOnlyHasNoValue(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Optional"})
	s.Init()
	typeText(t, s, "   ")
	if got := s.Value(); got != "" {
		t.Fatalf("Value=%q want empty", got)
	}
	if s.AutomationState().HasValue {
		t.Fatalf("HasValue=true for whitespace-only input")
	}
}

func TestHuhInputValidationSuccess(t *testing.T) {
	s := NewHuhInput(InputSpec{
		Title: "Port",
		Validate: func(v string) error {
			if v == "" {
				return errors.New("必須填寫")
			}
			return nil
		},
	})
	s.Init()
	typeText(t, s, "8080")
	send(t, s, keyEnter)
	if !s.Finished() || s.Canceled() {
		t.Fatalf("finished=%v canceled=%v", s.Finished(), s.Canceled())
	}
	if got := s.AutomationState().ValidationError; got != "" {
		t.Fatalf("ValidationError=%q want empty", got)
	}
}

func TestHuhInputValidationFailureKeepsScreenOpen(t *testing.T) {
	s := NewHuhInput(InputSpec{
		ScreenID: "port.input",
		Title:    "Port",
		Validate: func(v string) error {
			if v == "" {
				return errors.New("必須填寫")
			}
			return nil
		},
	})
	s.Init()
	send(t, s, keyEnter)
	if s.Finished() {
		t.Fatalf("a rejected value finished the screen")
	}
	if got := s.AutomationState().ValidationError; got != "必須填寫" {
		t.Fatalf("ValidationError=%q want the validator message", got)
	}
	// Fixing the value and re-submitting clears the error and commits.
	typeText(t, s, "9090")
	send(t, s, keyEnter)
	if !s.Finished() || s.Canceled() {
		t.Fatalf("finished=%v canceled=%v after a valid retry", s.Finished(), s.Canceled())
	}
	if got := s.AutomationState().ValidationError; got != "" {
		t.Fatalf("ValidationError=%q want empty after success", got)
	}
	if got := s.Value(); got != "9090" {
		t.Fatalf("Value=%q", got)
	}
}

// The validator must see the same trimmed text the router will store,
// not the raw keystrokes.
func TestHuhInputValidatorSeesTrimmedValue(t *testing.T) {
	var seen []string
	s := NewHuhInput(InputSpec{
		Title:    "Name",
		Validate: func(v string) error { seen = append(seen, v); return nil },
	})
	s.Init()
	typeText(t, s, "  bob  ")
	send(t, s, keyEnter)
	if len(seen) == 0 {
		t.Fatalf("validator never ran")
	}
	if last := seen[len(seen)-1]; last != "bob" {
		t.Fatalf("validator saw %q want the trimmed %q", last, "bob")
	}
}

func TestHuhInputEscCancels(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Realm", Default: "EXAMPLE.COM"})
	s.Init()
	cmd := send(t, s, keyEsc)
	if !s.Finished() || !s.Canceled() {
		t.Fatalf("finished=%v canceled=%v, want both true", s.Finished(), s.Canceled())
	}
	if cmd != nil {
		t.Fatalf("esc returned a command")
	}
}

func TestHuhInputCtrlCCancels(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Realm"})
	s.Init()
	cmd := send(t, s, keyCtrlC)
	if !s.Finished() || !s.Canceled() {
		t.Fatalf("finished=%v canceled=%v, want both true", s.Finished(), s.Canceled())
	}
	if cmd != nil {
		t.Fatalf("ctrl+c returned a command")
	}
}

func TestHuhInputEnterFinishesSynchronouslyAndLeaksNoCommand(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Realm", Default: "X"})
	s.Init()
	cmd := send(t, s, keyEnter)
	if !s.Finished() {
		t.Fatalf("Finished()=false immediately after enter")
	}
	if cmd != nil {
		t.Fatalf("enter returned a command; huh's field-advance cascade must be swallowed")
	}
}

func TestHuhInputScreenIDFallback(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Anything"})
	s.Init()
	if got := s.AutomationState().ScreenID; got != "text-input" {
		t.Fatalf("ScreenID=%q want the generic fallback %q", got, "text-input")
	}
}

// Core Invariant 6: a secret's typed text must never reach the rendered
// frame or the automation snapshot, while Value() still returns it for
// the real save path.
func TestHuhSecretInputNeverLeaksTypedValue(t *testing.T) {
	const sentinel = "s3cr3t-sentinel-9f2c"
	s := NewHuhInput(InputSpec{ScreenID: "vault.password", Title: "Vault password", Secret: true})
	s.Init()
	typeText(t, s, sentinel)

	if got := s.Value(); got != sentinel {
		t.Fatalf("Value=%q want the typed secret back for the save path", got)
	}

	view := s.View().Content
	if strings.Contains(view, sentinel) {
		t.Fatalf("rendered view leaked the secret")
	}
	for _, part := range []string{sentinel[:8], sentinel[len(sentinel)-8:]} {
		if strings.Contains(view, part) {
			t.Fatalf("rendered view leaked a fragment of the secret: %q", part)
		}
	}

	st := s.AutomationState()
	if !st.Secret {
		t.Fatalf("Secret=false on a secret input")
	}
	if !st.HasValue {
		t.Fatalf("HasValue=false after typing a secret")
	}
	if snapshot := fmt.Sprintf("%+v", st); strings.Contains(snapshot, sentinel) {
		t.Fatalf("AutomationState snapshot leaked the secret: %s", snapshot)
	}

	send(t, s, keyEnter)
	if !s.Finished() || s.Canceled() {
		t.Fatalf("finished=%v canceled=%v", s.Finished(), s.Canceled())
	}
	if got := s.Value(); got != sentinel {
		t.Fatalf("Value=%q after enter", got)
	}
}

func TestHuhSecretInputValidationErrorIsNotTheValue(t *testing.T) {
	const sentinel = "another-secret-af31"
	s := NewHuhInput(InputSpec{
		Title:    "Vault password",
		Secret:   true,
		Validate: func(string) error { return errors.New("密碼太短") },
	})
	s.Init()
	typeText(t, s, sentinel)
	send(t, s, keyEnter)
	if s.Finished() {
		t.Fatalf("a rejected secret finished the screen")
	}
	st := s.AutomationState()
	if st.ValidationError != "密碼太短" {
		t.Fatalf("ValidationError=%q", st.ValidationError)
	}
	if strings.Contains(fmt.Sprintf("%+v", st), sentinel) {
		t.Fatalf("validation path leaked the secret into the snapshot")
	}
}

func TestHuhInputFinishedScreenIgnoresFurtherKeys(t *testing.T) {
	s := NewHuhInput(InputSpec{Title: "Realm", Default: "A"})
	s.Init()
	send(t, s, keyEnter)
	typeText(t, s, "BBB")
	send(t, s, keyEsc)
	if s.Canceled() {
		t.Fatalf("a confirmed input was retroactively canceled")
	}
	if got := s.Value(); got != "A" {
		t.Fatalf("Value=%q changed after the screen finished", got)
	}
}
