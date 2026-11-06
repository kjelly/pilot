package identityreconcile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kjelly/pilot/internal/secretpath"
)

// The result file of the authorization-cache entry playbook and of the identity
// playbook's observation (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §5.4, §5.5). ansible-playbook's exit code says nothing about whether the
// obligation was written or read: with no host matched, or a task skipped, it
// exits 0 and writes nothing (internal/identityreconcile/testdata, captures
// authcache-k16-*). So Go trusts one thing only, a small JSON object the playbook
// wrote on the controller, and ParseAuthCacheResult accepts it only when every
// check below holds. A result that fails one is an entry failure (prepare, probe:
// Go writes nothing) or an unsettled obligation (observe: the caller decides, the
// writes already happened).

// AuthCacheSchema is the "schema" value of the result file.
const AuthCacheSchema = "pilot.identity-auth-cache/v1"

// AuthCacheOutputVar is the Ansible variable that holds the path of the result
// file: the entry playbook and the identity playbook's observation both read it,
// and neither defines it, so a run that was not handed one writes nothing.
const AuthCacheOutputVar = "pilot_identity_auth_cache_output"

// AuthCacheActionVar is the Ansible variable that selects the entry's mode.
const AuthCacheActionVar = "pilot_identity_auth_cache_action"

// authCacheMaxBytes bounds what is read from the result file: the objects are a
// few hundred bytes, and a file of another size is not one of them.
const authCacheMaxBytes = 16 << 10

// AuthCacheAction is what the result file says produced it.
type AuthCacheAction string

const (
	// AuthCachePrepare is the entry's prepare mode: the helper's auth_prepare.
	AuthCachePrepare AuthCacheAction = "prepare"
	// AuthCacheProbe is the entry's probe mode: the helper's read-only auth_inspect.
	AuthCacheProbe AuthCacheAction = "probe"
	// AuthCacheObserve is what the identity playbook records about its own run.
	AuthCacheObserve AuthCacheAction = "observe"
)

// ErrAuthCacheResult is wrapped by every error ParseAuthCacheResult returns, so a
// caller can tell "the result cannot be trusted" from an I/O failure.
var ErrAuthCacheResult = errors.New("authorization cache result rejected")

// AuthCacheResult is a result file that passed every check.
type AuthCacheResult struct {
	Action AuthCacheAction
	// Host is the inventory host the playbook ran on; FQDN is its hostname -f.
	Host string
	FQDN string

	// Previous (prepare): the obligation was already owed before this prepare.
	Previous bool
	// Pending (probe): the obligation is owed now.
	Pending bool

	// Observe: what the identity playbook's own run did. Acked is the one that
	// settles anything: the run acknowledged the obligation. Prepared: its
	// prepare task ran and succeeded. Dirty: what its settle task reported, nil
	// when the settle did not run. Refreshed: the client refresh ran for at least
	// one client and every client finished.
	Prepared  bool
	Dirty     *bool
	Refreshed bool
	Acked     bool
}

// AuthCacheWant is what the caller knows before it reads the file: which mode it
// ran, and which host it holds the lock on.
type AuthCacheWant struct {
	Action AuthCacheAction
	// Host is the inventory name of the locked host, compared exactly.
	Host string
	// FQDN is what the lock's own ssh reported (sshdial.Dialer.FQDN), compared
	// without regard to case.
	FQDN string
}

// authCacheFields are the keys a result of each action may carry, and no others.
var authCacheFields = map[AuthCacheAction][]string{
	AuthCachePrepare: {"schema", "action", "host", "fqdn", "previous"},
	AuthCacheProbe:   {"schema", "action", "host", "fqdn", "pending"},
	AuthCacheObserve: {"schema", "action", "host", "fqdn", "prepared", "dirty", "refreshed", "acked"},
}

func authCacheReject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAuthCacheResult, fmt.Sprintf(format, args...))
}

// ParseAuthCacheResult accepts the contents of a result file only when:
// ansible-playbook exited 0; the file is not empty and holds exactly one JSON
// object with no data after it and no key twice; its schema is AuthCacheSchema;
// its action is the one that was run; it carries exactly the keys of that action,
// with the right types; its host is the locked inventory host; and its fqdn is the
// locked host's. Anything else is an error that wraps ErrAuthCacheResult and says
// which check failed. A zero exit code with an empty file is the case that must
// never read as "nothing owed": it is what ansible-playbook does for a pattern
// that matches no host and for a skipped task.
func ParseAuthCacheResult(exitCode int, data []byte, want AuthCacheWant) (AuthCacheResult, error) {
	var res AuthCacheResult
	fields, ok := authCacheFields[want.Action]
	if !ok {
		return res, authCacheReject("the action asked for is %q, not one of prepare, probe or observe", want.Action) // gate: authcache-want-action
	}
	if want.Host == "" {
		return res, authCacheReject("no locked host to compare the result's host with") // gate: authcache-want-host
	}
	if want.FQDN == "" {
		return res, authCacheReject("no FQDN of the locked host to compare the result's fqdn with") // gate: authcache-want-fqdn
	}
	if exitCode != 0 {
		return res, authCacheReject("ansible-playbook exited %d", exitCode) // gate: authcache-exit
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return res, authCacheReject("the result file is empty: ansible-playbook exited 0 without writing the result (no host matched, or the task that writes it did not run)") // gate: authcache-empty
	}
	if len(data) > authCacheMaxBytes {
		return res, authCacheReject("the result file is %d bytes, more than the %d a result can be", len(data), authCacheMaxBytes) // gate: authcache-size
	}
	raw, err := decodeSingleObject(data)
	if err != nil {
		return res, authCacheReject("%v", err) // gate: authcache-shape
	}

	var schema string
	if err := authCacheString(raw, "schema", &schema); err != nil {
		return res, err // gate: authcache-schema-type
	}
	if schema != AuthCacheSchema {
		return res, authCacheReject("schema is %q, want %q", schema, AuthCacheSchema) // gate: authcache-schema
	}
	var action string
	if err := authCacheString(raw, "action", &action); err != nil {
		return res, err // gate: authcache-action-type
	}
	if AuthCacheAction(action) != want.Action {
		return res, authCacheReject("action is %q, want %q", action, want.Action) // gate: authcache-action
	}
	for key := range raw {
		if !slices.Contains(fields, key) {
			return res, authCacheReject("unexpected key %q in a %s result", key, want.Action) // gate: authcache-unexpected-key
		}
	}
	res.Action = want.Action
	if err := authCacheString(raw, "host", &res.Host); err != nil {
		return res, err // gate: authcache-host-type
	}
	if res.Host != want.Host {
		return res, authCacheReject("host is %q, but the lock is held on %q: another host's result", res.Host, want.Host) // gate: authcache-host
	}
	if err := authCacheString(raw, "fqdn", &res.FQDN); err != nil {
		return res, err // gate: authcache-fqdn-type
	}
	if !strings.EqualFold(res.FQDN, want.FQDN) {
		return res, authCacheReject("fqdn is %q, but the locked host reports %q", res.FQDN, want.FQDN) // gate: authcache-fqdn
	}

	switch want.Action {
	case AuthCachePrepare:
		if err := authCacheBool(raw, "previous", &res.Previous); err != nil {
			return res, err // gate: authcache-previous
		}
	case AuthCacheProbe:
		if err := authCacheBool(raw, "pending", &res.Pending); err != nil {
			return res, err // gate: authcache-pending
		}
	case AuthCacheObserve:
		for key, dst := range map[string]*bool{"prepared": &res.Prepared, "refreshed": &res.Refreshed, "acked": &res.Acked} {
			if err := authCacheBool(raw, key, dst); err != nil {
				return res, err // gate: authcache-observe-bool
			}
		}
		// dirty is the one key that may be null: the settle task did not run.
		value, present := raw["dirty"]
		if !present {
			return res, authCacheReject("observe result has no dirty key (it is null when the settle did not run)") // gate: authcache-observe-dirty-missing
		}
		if string(bytes.TrimSpace(value)) != "null" {
			var dirty bool
			if err := authCacheBool(raw, "dirty", &dirty); err != nil {
				return res, err // gate: authcache-observe-dirty-type
			}
			res.Dirty = &dirty
		}
	}
	return res, nil
}

// decodeSingleObject reads data as exactly one JSON object whose keys are
// distinct, and returns its values undecoded. encoding/json keeps the last of
// two equal keys and ignores them without a word, so the keys are read off the
// token stream first.
func decodeSingleObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("the result is not JSON: %v", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("the result is not a JSON object")
	}
	raw := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("the result is not valid JSON: %v", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("the result has a key that is not a string")
		}
		if _, dup := raw[key]; dup {
			return nil, fmt.Errorf("the result has the key %q twice", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("the value of %q is not valid JSON: %v", key, err)
		}
		raw[key] = value
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, fmt.Errorf("the result object is not closed: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("the result has data after its one JSON object")
	}
	return raw, nil
}

func authCacheString(raw map[string]json.RawMessage, key string, dst *string) error {
	value, ok := raw[key]
	if !ok {
		return authCacheReject("missing key %q", key)
	}
	if err := json.Unmarshal(value, dst); err != nil || bytes.HasPrefix(bytes.TrimSpace(value), []byte("null")) {
		return authCacheReject("%q is not a string: %s", key, bytes.TrimSpace(value))
	}
	if *dst == "" {
		return authCacheReject("%q is empty", key)
	}
	return nil
}

// authCacheBool accepts a JSON true or false and nothing else: "true", 1 and
// null are what a template that went wrong produces.
func authCacheBool(raw map[string]json.RawMessage, key string, dst *bool) error {
	value, ok := raw[key]
	if !ok {
		return authCacheReject("missing key %q", key)
	}
	switch string(bytes.TrimSpace(value)) {
	case "true":
		*dst = true
	case "false":
		*dst = false
	default:
		return authCacheReject("%q is not a JSON boolean: %s", key, bytes.TrimSpace(value))
	}
	return nil
}

// RenderAuthCacheResult writes res the way the playbooks do: one JSON object with
// the keys of its action, sorted. It is the other half of the round trip
// (AGENTS.md §5.15: what Parse accepts, Render writes, Parse reads back equal).
func RenderAuthCacheResult(res AuthCacheResult) ([]byte, error) {
	out := map[string]any{"schema": AuthCacheSchema, "action": string(res.Action), "host": res.Host, "fqdn": res.FQDN}
	switch res.Action {
	case AuthCachePrepare:
		out["previous"] = res.Previous
	case AuthCacheProbe:
		out["pending"] = res.Pending
	case AuthCacheObserve:
		out["prepared"], out["refreshed"], out["acked"] = res.Prepared, res.Refreshed, res.Acked
		if res.Dirty != nil {
			out["dirty"] = *res.Dirty
		} else {
			out["dirty"] = nil
		}
	default:
		return nil, fmt.Errorf("cannot render an authorization cache result of action %q", res.Action)
	}
	return json.Marshal(out)
}

// AuthCacheOutput is the result file of one run of an entry or an observing
// playbook: an empty 0600 file that Go makes before ansible-playbook starts, in a
// private directory, and reads after it. The playbook fills it on the controller.
// An empty file after the run is the proof that nothing was written, which no exit
// code gives.
type AuthCacheOutput struct {
	// Path is the absolute path to hand the playbook as AuthCacheOutputVar.
	Path string
	dir  string
}

// NewAuthCacheOutput makes the private directory and the empty result file.
func NewAuthCacheOutput() (*AuthCacheOutput, error) {
	dir, err := secretpath.PrivateTempDir("pilot-auth-cache")
	if err != nil {
		return nil, fmt.Errorf("make the directory for the authorization cache result: %w", err)
	}
	out := &AuthCacheOutput{Path: filepath.Join(dir, "result.json"), dir: dir}
	if err := out.Reset(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return out, nil
}

// Reset makes the file empty again, as a new file: whatever an earlier run left in
// it, or a file that something else put in its place, is gone. A run that is
// handed the path after Reset can only read back what it wrote itself. Call it
// before every ansible-playbook run that shares the path (spec §5.4).
func (o *AuthCacheOutput) Reset() error {
	if err := os.Remove(o.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear the authorization cache result file: %w", err)
	}
	f, err := os.OpenFile(o.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create the authorization cache result file: %w", err)
	}
	return f.Close()
}

// Read returns the file's contents. It refuses a file that is not a regular
// file or that holds more than a result can: a symlink or a device put in its
// place would be read as if the playbook had written it.
func (o *AuthCacheOutput) Read() ([]byte, error) {
	info, err := os.Lstat(o.Path)
	if err != nil {
		return nil, fmt.Errorf("read the authorization cache result file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, authCacheReject("the result file is not a regular file (%s)", info.Mode().Type())
	}
	if info.Size() > authCacheMaxBytes {
		return nil, authCacheReject("the result file is %d bytes, more than the %d a result can be", info.Size(), authCacheMaxBytes)
	}
	return os.ReadFile(o.Path)
}

// ExtraVars is the JSON object form of -e that hands the playbook the path (and
// the entry's action, when it is not empty): the form that survives a path with a
// space in it, which key=value does not (Ansible splits the value at the blank).
func (o *AuthCacheOutput) ExtraVars(action AuthCacheAction) (string, error) {
	vars := map[string]string{AuthCacheOutputVar: o.Path}
	if action != "" {
		vars[AuthCacheActionVar] = string(action)
	}
	b, err := json.Marshal(vars)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Close removes the file and its directory.
func (o *AuthCacheOutput) Close() error { return os.RemoveAll(o.dir) }
