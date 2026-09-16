// Package outbound implements Pilot's outbound state webhook: a durable,
// versioned, sanitized "user_host_access_v1" projection of Pilot's own
// declarative state, published to external HTTP consumers at the
// terminal boundary of pilot deploy/reconcile (and the dedicated
// gateway-scope/access reconcile/breakglass frontends). See
// docs/tmp/now/spec.md for the full design and docs/verification/
// outbound-webhook.md for the acceptance contract.
//
// This file (config.go) is the workspace's integrations.yaml parser and
// validator (design spec §7). A missing integrations.yaml means outbound
// publishing is disabled — this file must never itself open a store,
// read a secret, or make a network call; it only ever parses bytes into
// a validated, in-memory Config.
package outbound

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/contract"
)

// OperationKind is the top-level operation a webhook subscription
// matches against (design spec §1: deploy or reconcile only in V1).
type OperationKind string

const (
	OperationDeploy    OperationKind = "deploy"
	OperationReconcile OperationKind = "reconcile"
)

// ResultClass is the terminal result a webhook subscription matches
// against.
type ResultClass string

const (
	ResultSuccess   ResultClass = "success"
	ResultFailure   ResultClass = "failure"
	ResultCancelled ResultClass = "cancelled"
)

// PayloadMode selects what a matched event carries.
type PayloadMode string

const (
	PayloadSnapshot PayloadMode = "snapshot"
	PayloadDiff     PayloadMode = "diff"
	PayloadBoth     PayloadMode = "both"
)

// AuthType is the supported V1 webhook authentication mode. There is no
// unauthenticated mode (design spec §7.4).
type AuthType string

const (
	AuthHMACSHA256 AuthType = "hmac_sha256"
	AuthBearer     AuthType = "bearer"
)

// ProjectionUserHostAccessV1 is the only V1 projection name.
const ProjectionUserHostAccessV1 = "user_host_access_v1"

// Delivery defaults (design spec §7.4).
const (
	DefaultDeliveryTimeout        = 5 * time.Second
	DefaultDeliveryMaxAttempts    = 10
	DefaultDeliveryInitialBackoff = 30 * time.Second
	DefaultDeliveryMaxBackoff     = 30 * time.Minute
)

// Delivery bounds (design spec §7.4).
const (
	minDeliveryTimeout  = 100 * time.Millisecond
	maxDeliveryTimeout  = 30 * time.Second
	minDeliveryAttempts = 1
	maxDeliveryAttempts = 100
	minInitialBackoff   = 1 * time.Second
	maxBackoffAbsolute  = 24 * time.Hour
	minWebhookCount     = 1
	maxWebhookCount     = 16
)

var (
	sourceIDRegex    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	webhookNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	secretEnvRegex   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	// effectExactRegex mirrors contract.go's own effect-naming rule
	// (design spec §6.2); every value in contract.KnownEffects() already
	// matches it, so this is only used to reject a config-declared effect
	// string before even checking registry membership (a clearer error
	// for "identity/*" style typos than a bare "unknown effect").
	effectExactRegex   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	effectWildcardName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.\*$`)
)

// Config is a workspace's parsed, validated integrations.yaml.
type Config struct {
	SchemaVersion int
	SourceID      string
	Webhooks      []WebhookConfig
}

// WebhookConfig is one `webhooks[]` entry.
type WebhookConfig struct {
	Name       string
	Enabled    bool
	Endpoint   string
	Projection string
	Events     []EventRule
	Auth       AuthConfig
	TLS        TLSConfig
	Delivery   DeliveryConfig
}

// EventRule is one `events[]` entry: which (operation, result[, effects])
// combination publishes, and what payload mode.
type EventRule struct {
	Operation  OperationKind
	Result     ResultClass
	EffectsAny []string
	Payload    PayloadMode
}

// AuthConfig names the auth mode and the environment variable holding
// the secret. The secret value itself is never part of this struct.
type AuthConfig struct {
	Type      AuthType
	SecretEnv string
}

// TLSConfig is a webhook's transport trust configuration.
type TLSConfig struct {
	CAFile            string
	AllowInsecureHTTP bool
}

// DeliveryConfig is a webhook's timeout/retry policy.
type DeliveryConfig struct {
	Timeout        time.Duration
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// --- raw (presence-tracking) decode shapes -------------------------------
//
// design spec §7.3: "Raw YAML decoding MUST retain field-presence
// information for `enabled` and every delivery field ... V1 不允許因 Go
// zero value 而默默把「漏寫」解讀為另一種安全策略." Pointers (and, for
// durations, *string parsed explicitly) are how this file tells "field
// absent, use default" apart from "field present with the zero value".

type rawConfig struct {
	SchemaVersion int                `yaml:"schema_version"`
	SourceID      string             `yaml:"source_id"`
	Webhooks      []rawWebhookConfig `yaml:"webhooks"`
}

type rawWebhookConfig struct {
	Name       string            `yaml:"name"`
	Enabled    *bool             `yaml:"enabled"`
	Endpoint   string            `yaml:"endpoint"`
	Projection string            `yaml:"projection"`
	Events     []rawEventRule    `yaml:"events"`
	Auth       rawAuthConfig     `yaml:"auth"`
	TLS        rawTLSConfig      `yaml:"tls"`
	Delivery   rawDeliveryConfig `yaml:"delivery"`
}

type rawEventRule struct {
	Operation  string   `yaml:"operation"`
	Result     string   `yaml:"result"`
	EffectsAny []string `yaml:"effects_any"`
	Payload    string   `yaml:"payload"`
}

type rawAuthConfig struct {
	Type      string `yaml:"type"`
	SecretEnv string `yaml:"secret_env"`
}

type rawTLSConfig struct {
	CAFile            string `yaml:"ca_file"`
	AllowInsecureHTTP *bool  `yaml:"allow_insecure_http"`
}

type rawDeliveryConfig struct {
	Timeout        *string `yaml:"timeout"`
	MaxAttempts    *int    `yaml:"max_attempts"`
	InitialBackoff *string `yaml:"initial_backoff"`
	MaxBackoff     *string `yaml:"max_backoff"`
}

// DefaultConfigPath returns the default integrations.yaml path for a
// workspace directory (design spec §7.1).
func DefaultConfigPath(workspaceDir string) string {
	return filepath.Join(workspaceDir, "integrations.yaml")
}

// LoadConfigFile reads and validates a workspace's integrations.yaml. A
// missing file returns (nil, nil): outbound publishing is simply
// disabled, with no warning and no side effect (design spec §7.1, §37 —
// the documented fast path for a workspace that never opted in).
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("outbound: read %s: %w", path, err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("outbound: %s: %w", path, err)
	}
	return cfg, nil
}

// ParseConfig decodes and validates integrations.yaml content. Unknown
// YAML fields are rejected (design spec §7.4's last rule).
func ParseConfig(data []byte) (*Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode integrations.yaml: %w", err)
	}
	cfg, err := buildConfig(raw)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func buildConfig(raw rawConfig) (*Config, error) {
	cfg := &Config{SchemaVersion: raw.SchemaVersion, SourceID: raw.SourceID}
	cfg.Webhooks = make([]WebhookConfig, 0, len(raw.Webhooks))
	for _, rw := range raw.Webhooks {
		if rw.Enabled == nil {
			name := rw.Name
			if name == "" {
				name = "(unnamed)"
			}
			return nil, fmt.Errorf("webhook %q: enabled must be explicitly true or false", name)
		}
		w := WebhookConfig{
			Name:       rw.Name,
			Enabled:    *rw.Enabled,
			Endpoint:   rw.Endpoint,
			Projection: rw.Projection,
			Auth:       AuthConfig{Type: AuthType(rw.Auth.Type), SecretEnv: rw.Auth.SecretEnv},
			TLS:        TLSConfig{CAFile: rw.TLS.CAFile},
		}
		if rw.TLS.AllowInsecureHTTP != nil {
			w.TLS.AllowInsecureHTTP = *rw.TLS.AllowInsecureHTTP
		}
		for _, re := range rw.Events {
			w.Events = append(w.Events, EventRule{
				Operation:  OperationKind(re.Operation),
				Result:     ResultClass(re.Result),
				EffectsAny: append([]string(nil), re.EffectsAny...),
				Payload:    PayloadMode(re.Payload),
			})
		}
		delivery, err := buildDelivery(rw.Delivery)
		if err != nil {
			return nil, fmt.Errorf("webhook %q: %w", rw.Name, err)
		}
		w.Delivery = delivery
		cfg.Webhooks = append(cfg.Webhooks, w)
	}
	return cfg, nil
}

func buildDelivery(rd rawDeliveryConfig) (DeliveryConfig, error) {
	d := DeliveryConfig{
		Timeout:        DefaultDeliveryTimeout,
		MaxAttempts:    DefaultDeliveryMaxAttempts,
		InitialBackoff: DefaultDeliveryInitialBackoff,
		MaxBackoff:     DefaultDeliveryMaxBackoff,
	}
	if rd.Timeout != nil {
		v, err := time.ParseDuration(*rd.Timeout)
		if err != nil {
			return d, fmt.Errorf("delivery.timeout: %w", err)
		}
		d.Timeout = v
	}
	if rd.MaxAttempts != nil {
		d.MaxAttempts = *rd.MaxAttempts
	}
	if rd.InitialBackoff != nil {
		v, err := time.ParseDuration(*rd.InitialBackoff)
		if err != nil {
			return d, fmt.Errorf("delivery.initial_backoff: %w", err)
		}
		d.InitialBackoff = v
	}
	if rd.MaxBackoff != nil {
		v, err := time.ParseDuration(*rd.MaxBackoff)
		if err != nil {
			return d, fmt.Errorf("delivery.max_backoff: %w", err)
		}
		d.MaxBackoff = v
	}
	return d, nil
}

// Validate runs every pure, filesystem-free schema check (design spec
// §7.4): required fields, enums, URL shape, bounds, and duplicate
// identity. It applies identically to enabled and disabled webhook
// entries. It never touches the filesystem or the network — see
// CheckReadiness for the checks that do.
func (c *Config) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1, got %d", c.SchemaVersion)
	}
	if !sourceIDRegex.MatchString(c.SourceID) {
		return fmt.Errorf("source_id %q must match %s", c.SourceID, sourceIDRegex.String())
	}
	if len(c.Webhooks) < minWebhookCount || len(c.Webhooks) > maxWebhookCount {
		return fmt.Errorf("webhooks must have %d..%d entries, got %d", minWebhookCount, maxWebhookCount, len(c.Webhooks))
	}
	names := make(map[string]bool, len(c.Webhooks))
	for i := range c.Webhooks {
		w := &c.Webhooks[i]
		if !webhookNameRegex.MatchString(w.Name) {
			return fmt.Errorf("webhook name %q must match %s", w.Name, webhookNameRegex.String())
		}
		if names[w.Name] {
			return fmt.Errorf("duplicate webhook name %q", w.Name)
		}
		names[w.Name] = true
		if err := w.validate(); err != nil {
			return fmt.Errorf("webhook %q: %w", w.Name, err)
		}
	}
	return nil
}

func (w *WebhookConfig) validate() error {
	if err := validateEndpoint(w.Endpoint, w.TLS.AllowInsecureHTTP); err != nil {
		return err
	}
	if w.Projection != ProjectionUserHostAccessV1 {
		return fmt.Errorf("projection must be %q, got %q", ProjectionUserHostAccessV1, w.Projection)
	}
	if len(w.Events) == 0 {
		return fmt.Errorf("at least one event rule is required")
	}
	seen := make(map[[2]string]bool, len(w.Events))
	for _, ev := range w.Events {
		if ev.Operation != OperationDeploy && ev.Operation != OperationReconcile {
			return fmt.Errorf("event operation must be deploy or reconcile, got %q", ev.Operation)
		}
		if ev.Result != ResultSuccess && ev.Result != ResultFailure && ev.Result != ResultCancelled {
			return fmt.Errorf("event result must be success, failure, or cancelled, got %q", ev.Result)
		}
		key := [2]string{string(ev.Operation), string(ev.Result)}
		if seen[key] {
			return fmt.Errorf("duplicate event rule for (%s, %s)", ev.Operation, ev.Result)
		}
		seen[key] = true
		if ev.Payload != PayloadSnapshot && ev.Payload != PayloadDiff && ev.Payload != PayloadBoth {
			return fmt.Errorf("event payload must be snapshot, diff, or both, got %q", ev.Payload)
		}
		if err := validateEffectsAny(ev.EffectsAny, ev.Operation); err != nil {
			return err
		}
	}
	if err := validateAuth(w.Auth); err != nil {
		return err
	}
	if err := validateTLSSchema(w.TLS); err != nil {
		return err
	}
	if err := validateDelivery(w.Delivery); err != nil {
		return err
	}
	return nil
}

func validateEndpoint(raw string, allowInsecureHTTP bool) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("endpoint is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("endpoint must be an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecureHTTP {
			return fmt.Errorf("endpoint scheme must be https (set tls.allow_insecure_http: true to opt into http)")
		}
	default:
		return fmt.Errorf("endpoint scheme must be https or http, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("endpoint host is required")
	}
	if u.User != nil {
		return fmt.Errorf("endpoint must not contain userinfo")
	}
	if u.RawQuery != "" {
		return fmt.Errorf("endpoint must not contain a query string")
	}
	if u.Fragment != "" {
		return fmt.Errorf("endpoint must not contain a fragment")
	}
	return nil
}

func validateAuth(a AuthConfig) error {
	if a.Type != AuthHMACSHA256 && a.Type != AuthBearer {
		return fmt.Errorf("auth.type must be hmac_sha256 or bearer, got %q", a.Type)
	}
	if !secretEnvRegex.MatchString(a.SecretEnv) {
		return fmt.Errorf("auth.secret_env %q must match %s", a.SecretEnv, secretEnvRegex.String())
	}
	return nil
}

func validateTLSSchema(t TLSConfig) error {
	if t.CAFile != "" && !filepath.IsAbs(t.CAFile) {
		return fmt.Errorf("tls.ca_file must be an absolute path, got %q", t.CAFile)
	}
	return nil
}

func validateDelivery(d DeliveryConfig) error {
	if d.Timeout < minDeliveryTimeout || d.Timeout > maxDeliveryTimeout {
		return fmt.Errorf("delivery.timeout %s out of bounds [%s,%s]", d.Timeout, minDeliveryTimeout, maxDeliveryTimeout)
	}
	if d.MaxAttempts < minDeliveryAttempts || d.MaxAttempts > maxDeliveryAttempts {
		return fmt.Errorf("delivery.max_attempts %d out of bounds [%d,%d]", d.MaxAttempts, minDeliveryAttempts, maxDeliveryAttempts)
	}
	if d.InitialBackoff < minInitialBackoff || d.InitialBackoff > maxBackoffAbsolute {
		return fmt.Errorf("delivery.initial_backoff %s out of bounds [%s,%s]", d.InitialBackoff, minInitialBackoff, maxBackoffAbsolute)
	}
	if d.MaxBackoff < d.InitialBackoff || d.MaxBackoff > maxBackoffAbsolute {
		return fmt.Errorf("delivery.max_backoff %s out of bounds [initial_backoff=%s,%s]", d.MaxBackoff, d.InitialBackoff, maxBackoffAbsolute)
	}
	return nil
}

// knownEffectSet and knownEffectNamespaces back effects_any validation
// (design spec §7.5, §31): an exact value must be a real contract
// effect, and a wildcard's namespace must be a real prefix of one.
func knownEffectSet() map[string]bool {
	set := make(map[string]bool)
	for _, e := range contract.KnownEffects() {
		set[string(e)] = true
	}
	return set
}

func knownEffectNamespaces() map[string]bool {
	set := make(map[string]bool)
	for _, e := range contract.KnownEffects() {
		if i := strings.IndexByte(string(e), '.'); i > 0 {
			set[string(e)[:i]] = true
		}
	}
	return set
}

func validateEffectsAny(effectsAny []string, operation OperationKind) error {
	if operation == OperationDeploy && len(effectsAny) > 0 {
		return fmt.Errorf("effects_any is not allowed on an operation=deploy rule")
	}
	if len(effectsAny) == 0 {
		return nil
	}
	known := knownEffectSet()
	namespaces := knownEffectNamespaces()
	for _, e := range effectsAny {
		if strings.HasSuffix(e, ".*") {
			prefix := strings.TrimSuffix(e, ".*")
			if !effectWildcardName.MatchString(e) {
				return fmt.Errorf("invalid effect wildcard %q", e)
			}
			if !namespaces[prefix] {
				return fmt.Errorf("effect wildcard %q does not match a known effect namespace", e)
			}
			continue
		}
		if !effectExactRegex.MatchString(e) || !known[e] {
			return fmt.Errorf("unknown effect %q", e)
		}
	}
	return nil
}

// CheckReadiness performs the pre-mutation, filesystem-touching checks
// Validate() deliberately does not (design spec §7.4, §21, INV-3): for
// every ENABLED webhook whose tls.ca_file is set, the file must exist, be
// a regular file, and contain at least one parseable PEM certificate.
// Disabled webhooks are skipped entirely. A missing auth secret
// environment variable is NOT checked here — that is a runtime delivery
// failure (INV-2/INV-3: it leaves the event pending with
// last_error_class=missing_auth_secret, it never blocks the operation).
func (c *Config) CheckReadiness() error {
	for _, w := range c.Webhooks {
		if !w.Enabled || w.TLS.CAFile == "" {
			continue
		}
		info, err := os.Stat(w.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("webhook %q: tls.ca_file %s: %w", w.Name, w.TLS.CAFile, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("webhook %q: tls.ca_file %s is not a regular file", w.Name, w.TLS.CAFile)
		}
		pemData, err := os.ReadFile(w.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("webhook %q: tls.ca_file %s: %w", w.Name, w.TLS.CAFile, err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pemData) {
			return fmt.Errorf("webhook %q: tls.ca_file %s contains no parseable PEM certificate", w.Name, w.TLS.CAFile)
		}
	}
	return nil
}
