package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Capability identifies an independently consumable shared cache.
type Capability string

const (
	APT Capability = "apt"
	RPM Capability = "rpm"
	OCI Capability = "oci"
)

// Requirements is nil only when omitted. An explicitly empty selection is invalid.
type Requirements []Capability

func NormalizeRequirements(in Requirements) (Requirements, error) {
	if in == nil {
		return Requirements{APT, RPM, OCI}, nil
	}
	if len(in) == 0 {
		return nil, errors.New("services: capability selection must not be empty")
	}
	seen := map[Capability]bool{}
	for _, c := range in {
		if c != APT && c != RPM && c != OCI {
			return nil, fmt.Errorf("services: unknown capability %q", c)
		}
		if seen[c] {
			return nil, fmt.Errorf("services: duplicate capability %q", c)
		}
		seen[c] = true
	}
	out := Requirements{}
	for _, c := range []Capability{APT, RPM, OCI} {
		if seen[c] {
			out = append(out, c)
		}
	}
	return out, nil
}
func ParseRequirements(raw string) (Requirements, error) {
	if raw == "" {
		return nil, errors.New("services: capability selection must not be empty")
	}
	out := Requirements{}
	for _, c := range strings.Split(raw, ",") {
		out = append(out, Capability(strings.TrimSpace(c)))
	}
	return NormalizeRequirements(out)
}
func (r Requirements) Has(c Capability) bool {
	n, e := NormalizeRequirements(r)
	return e == nil && slices.Contains(n, c)
}

// DataProbe defines a bounded real cache read. APT Resource is an upstream URL;
// RPM and OCI Resource are absolute paths on their respective cache endpoint.
type DataProbe struct {
	Resource string `yaml:"resource" json:"resource"`
	SHA256   string `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	Contains string `yaml:"contains,omitempty" json:"contains,omitempty"`
}

func (p DataProbe) Validate(c Capability) error {
	u, e := url.Parse(p.Resource)
	if e != nil || p.Resource == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(p.Resource, "\r\n\t") {
		return errors.New("services: invalid data probe resource")
	}
	if c == APT {
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("services: apt data probe must name an upstream URL")
		}
	} else if u.Scheme != "" || u.Host != "" || !strings.HasPrefix(p.Resource, "/") || strings.HasPrefix(p.Resource, "//") {
		return errors.New("services: data probe must name an endpoint-relative absolute path")
	}
	if p.SHA256 != "" {
		b, e := hex.DecodeString(p.SHA256)
		if e != nil || len(b) != 32 {
			return errors.New("services: invalid data probe SHA-256")
		}
	}
	if p.SHA256 == "" && p.Contains == "" {
		return errors.New("services: data probe needs a content expectation")
	}
	if c == OCI && (p.SHA256 == "" || !strings.HasPrefix(p.Resource, "/v2/") || (!strings.Contains(p.Resource, "/manifests/sha256:"+p.SHA256) && !strings.Contains(p.Resource, "/blobs/sha256:"+p.SHA256))) {
		return errors.New("services: oci data probe requires an immutable manifest/blob digest path and matching SHA-256")
	}
	return nil
}

// ClientDataProbes derives safe package metadata reads without inventing OCI digests.
func (p Profile) ClientDataProbes() map[Capability]DataProbe {
	out := map[Capability]DataProbe{APT: {Resource: strings.TrimRight(p.Apt.Upstream, "/") + "/dists/noble/InRelease", Contains: "-----BEGIN PGP SIGNED MESSAGE-----"}}
	if len(p.RPM.Repos) > 0 {
		out[RPM] = DataProbe{Resource: "/pulp/content/" + p.Name + "/" + p.RPM.Repos[0].Name + "/repodata/repomd.xml", Contains: "<repomd"}
	}
	for c, v := range p.DataProbes {
		out[c] = v
	}
	return out
}

// ProbeResult deliberately contains no upstream body, credentials or raw errors.
type ProbeResult struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}
type CapabilityStatus struct {
	Initialization ProbeResult `json:"initialization"`
	Health         ProbeResult `json:"health"`
	ManagementAuth ProbeResult `json:"management_auth"`
	Data           ProbeResult `json:"data"`
	ObservedAt     time.Time   `json:"observed_at"`
}

func good() ProbeResult                { return ProbeResult{State: "ready"} }
func failed(reason string) ProbeResult { return ProbeResult{State: "failed", Reason: reason} }

const probeBodyLimit = 8 * 1024 * 1024
const probeRequestTimeout = 2 * time.Second
const probeTotalTimeout = 10 * time.Second

// observeCapabilities performs one attempt per read, in parallel per capability.
// No lifecycle commands, credential publication or persisted observations occur.
func (m *Manager) observeCapabilities(ctx context.Context, s ServiceState) map[Capability]CapabilityStatus {
	ctx, cancel := context.WithTimeout(ctx, probeTotalTimeout)
	defer cancel()
	type result struct {
		c Capability
		s CapabilityStatus
	}
	ch := make(chan result, 3)
	for _, c := range []Capability{APT, RPM, OCI} {
		go func(c Capability) { ch <- result{c, m.observeCapability(ctx, s, c)} }(c)
	}
	out := map[Capability]CapabilityStatus{}
	for range 3 {
		r := <-ch
		out[r.c] = r.s
	}
	return out
}
func (m *Manager) readProbe(ctx context.Context, raw, host, secret string, proxy *url.URL) ([]byte, int, error) {
	b, c, _, e := m.readProbeHeaders(ctx, raw, host, secret, "", proxy)
	return b, c, e
}
func (m *Manager) readProbeHeaders(ctx context.Context, raw, host, secret, bearer string, proxy *url.URL) ([]byte, int, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, probeRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	if host != "" {
		req.Host = host
	}
	if secret != "" {
		req.SetBasicAuth("admin", secret)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/json, */*")
	client := *m.client
	client.Timeout = probeRequestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if proxy != nil && (m.client.Transport == nil || isHTTPTransport(m.client.Transport)) {
		base, ok := m.client.Transport.(*http.Transport)
		if !ok || base == nil {
			base = http.DefaultTransport.(*http.Transport)
		}
		transport := base.Clone()
		transport.Proxy = http.ProxyURL(proxy)
		defer transport.CloseIdleConnections()
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit+1))
	if err != nil || len(body) > probeBodyLimit {
		return nil, resp.StatusCode, resp.Header, errors.New("invalid or oversized body")
	}
	return body, resp.StatusCode, resp.Header, nil
}
func nativeHealth(c Capability, body []byte) bool {
	if c == APT {
		return (strings.Contains(strings.ToLower(string(body)), "apt-cacher-ng") || strings.Contains(strings.ToLower(string(body)), "apt-cacher ng")) && strings.Contains(strings.ToLower(string(body)), "<html")
	}
	if c == OCI {
		var v struct {
			Status     string `json:"status"`
			Components []struct {
				Status string `json:"status"`
			} `json:"components"`
		}
		if json.Unmarshal(body, &v) != nil || v.Status != "healthy" || len(v.Components) == 0 {
			return false
		}
		for _, x := range v.Components {
			if x.Status != "healthy" {
				return false
			}
		}
		return true
	}
	var v struct {
		Database struct {
			Connected bool `json:"connected"`
		} `json:"database_connection"`
		Redis struct {
			Connected bool `json:"connected"`
		} `json:"redis_connection"`
		Workers []struct {
			Name string `json:"name"`
		} `json:"online_workers"`
		Content []struct {
			Name string `json:"name"`
		} `json:"online_content_apps"`
	}
	if json.Unmarshal(body, &v) != nil || !v.Database.Connected || len(v.Workers) == 0 || len(v.Content) == 0 {
		return false
	}
	for _, x := range v.Workers {
		if x.Name == "" {
			return false
		}
	}
	for _, x := range v.Content {
		if x.Name == "" {
			return false
		}
	}
	return true
}
func (m *Manager) observeCapability(ctx context.Context, s ServiceState, c Capability) CapabilityStatus {
	now := m.now().UTC()
	o := CapabilityStatus{ObservedAt: now, Initialization: ProbeResult{State: "unknown", Reason: "native-readiness-unproven"}, Health: ProbeResult{State: "unknown"}, ManagementAuth: ProbeResult{State: "unknown"}, Data: ProbeResult{State: "unknown", Reason: "missing-descriptor-configure-profile-data_probes"}}
	raw, path := s.Client.AptProxyURL, "/acng-report.html"
	if c == RPM {
		raw, path = s.Client.RPMBaseURL, "/pulp/api/v3/status/"
	}
	if c == OCI {
		raw, path = s.Client.RegistryMirrorURL, "/api/v2.0/health"
	}
	endpoint, e := serviceProbeURL(raw, net.ParseIP(s.BindIP), path)
	if e != nil {
		o.Health = failed("invalid-endpoint")
		return o
	}
	u, _ := url.Parse(raw)
	body, code, e := m.readProbe(ctx, endpoint, u.Host, "", nil)
	if e != nil {
		o.Health = failed("transport-or-timeout")
	} else if code != 200 {
		o.Health = failed(fmt.Sprintf("http-%d", code))
	} else if !nativeHealth(c, body) {
		o.Health = failed("native-unhealthy-or-malformed")
	} else {
		o.Health = good()
	}
	if c == APT {
		o.ManagementAuth = ProbeResult{State: "not-applicable"}
	} else {
		var secret string
		if c == OCI {
			secret, e = readHarborAdminPassword(s.Root)
			path = "/api/v2.0/users/current"
		} else {
			secret, e = readPulpAdminPassword(s.Root)
			path = "/pulp/api/v3/users/?limit=1"
		}
		if e != nil {
			o.ManagementAuth = failed("credential-unavailable")
		} else {
			endpoint, _ = serviceProbeURL(raw, net.ParseIP(s.BindIP), path)
			body, code, e = m.readProbe(ctx, endpoint, u.Host, secret, nil)
			if e != nil {
				o.ManagementAuth = failed("transport-or-timeout")
			} else if code != 200 {
				o.ManagementAuth = failed(fmt.Sprintf("http-%d", code))
			} else {
				var v map[string]json.RawMessage
				if json.Unmarshal(body, &v) != nil {
					o.ManagementAuth = failed("malformed-response")
				} else if c == OCI {
					var username string
					var admin bool
					_ = json.Unmarshal(v["username"], &username)
					_ = json.Unmarshal(v["sysadmin_flag"], &admin)
					if username != "admin" || !admin {
						o.ManagementAuth = failed("management-identity-rejected")
					} else {
						o.ManagementAuth = good()
					}
				} else if v["results"] == nil {
					o.ManagementAuth = failed("malformed-response")
				} else {
					o.ManagementAuth = good()
				}
			}
		}
	}
	descriptor, ok := s.Client.DataProbes[c]
	if !ok {
		return o
	}
	if descriptor.Validate(c) != nil {
		o.Data = failed("invalid-descriptor")
		return o
	}
	var proxy *url.URL
	host := u.Host
	if c == APT {
		endpoint = descriptor.Resource
		host = ""
		proxy, _ = url.Parse(raw)
		proxy.Host = net.JoinHostPort(s.BindIP, proxy.Port())
	} else {
		endpoint, e = serviceProbeURL(raw, net.ParseIP(s.BindIP), descriptor.Resource)
		if e != nil {
			o.Data = failed("invalid-endpoint")
			return o
		}
	}
	if c == OCI {
		body, code, e = m.readOCIData(ctx, endpoint, u, descriptor.Resource, s.BindIP)
	} else {
		body, code, e = m.readProbe(ctx, endpoint, host, "", proxy)
	}
	if e != nil {
		o.Data = failed("transport-or-timeout")
	} else if code != 200 {
		o.Data = failed(fmt.Sprintf("http-%d", code))
	} else {
		sum := sha256.Sum256(body)
		if (descriptor.SHA256 != "" && hex.EncodeToString(sum[:]) != descriptor.SHA256) || (descriptor.Contains != "" && !strings.Contains(string(body), descriptor.Contains)) {
			o.Data = failed("content-mismatch")
		} else {
			o.Data = good()
		}
	}
	if o.Health.State == "ready" && o.Data.State == "ready" {
		o.Initialization = good()
	}
	return o
}
func requireCapabilities(observed map[Capability]CapabilityStatus, required Requirements) error {
	required, e := NormalizeRequirements(required)
	if e != nil {
		return e
	}
	for _, c := range required {
		s := observed[c]
		if s.Health.State != "ready" || s.Data.State != "ready" {
			return fmt.Errorf("services: required %s cache is not ready (health=%s:%s data=%s:%s)", c, s.Health.State, s.Health.Reason, s.Data.State, s.Data.Reason)
		}
	}
	return nil
}

// ClientConfigFor validates the required data planes independently of management.
func (m *Manager) ClientConfigFor(ctx context.Context, required Requirements) (ClientConfig, error) {
	if _, e := NormalizeRequirements(required); e != nil {
		return ClientConfig{}, e
	}
	unlock, e := m.operationContext(ctx)
	if e != nil {
		return ClientConfig{}, e
	}
	defer unlock()
	s, e := m.current()
	if e != nil {
		return ClientConfig{}, e
	}
	if s.Fingerprint == "" {
		return ClientConfig{}, errors.New("services: service stack is not configured")
	}
	observed := m.observeCapabilities(ctx, s)
	if ctx.Err() != nil {
		return ClientConfig{}, ctx.Err()
	}
	if e = requireCapabilities(observed, required); e != nil {
		return ClientConfig{}, e
	}
	if s.Client.HostIP == "" {
		s.Client.HostIP = s.BindIP
	}
	return s.Client, nil
}

// validateConsumptionData retains physical identity/CA checks without management secrets.
func validateConsumptionData(s ServiceState) error {
	if s.Client.Profile != s.Profile || s.Client.Fingerprint != s.Fingerprint || s.Client.InstanceID != s.InstanceID || s.Client.Generation != s.Generation {
		return errors.New("services: registered client identity is inconsistent")
	}
	if s.ComposePath == "" {
		return errors.New("services: registered Compose root unavailable")
	}
	ca, e := readCAPEM(s.Root)
	if e != nil || ca == "" || strings.TrimSpace(ca) != strings.TrimSpace(s.Client.CAPEM) {
		return errors.New("services: registered CA identity unavailable")
	}
	return nil
}

var bearerParameter = regexp.MustCompile(`([a-z]+)="([^"\r\n]*)"`)

// readOCIData implements only anonymous, same-origin Distribution token challenges.
// It never forwards management credentials or accepts a challenge as data proof.
func (m *Manager) readOCIData(ctx context.Context, endpoint string, origin *url.URL, resource, bindIP string) ([]byte, int, error) {
	body, code, header, err := m.readProbeHeaders(ctx, endpoint, origin.Host, "", "", nil)
	if err != nil || code != 401 {
		return body, code, err
	}
	challenge := header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") {
		return nil, code, errors.New("unsupported registry challenge")
	}
	params := map[string]string{}
	for _, match := range bearerParameter.FindAllStringSubmatch(strings.TrimPrefix(challenge, "Bearer "), -1) {
		if _, ok := params[match[1]]; ok {
			return nil, code, errors.New("ambiguous registry challenge")
		}
		params[match[1]] = match[2]
	}
	realm, e := url.Parse(params["realm"])
	if e != nil || realm.Scheme != origin.Scheme || (realm.Port() != origin.Port() || (realm.Hostname() != origin.Hostname() && realm.Hostname() != bindIP)) || realm.User != nil || realm.Fragment != "" || realm.RawQuery != "" || realm.Path != "/service/token" {
		return nil, code, errors.New("unsafe registry challenge realm")
	}
	repository := strings.TrimPrefix(resource, "/v2/")
	for _, separator := range []string{"/manifests/", "/blobs/"} {
		if i := strings.Index(repository, separator); i >= 0 {
			repository = repository[:i]
			break
		}
	}
	if params["scope"] != "repository:"+repository+":pull" || params["service"] == "" {
		return nil, code, errors.New("unsafe registry challenge scope")
	}
	q := realm.Query()
	q.Set("service", params["service"])
	q.Set("scope", params["scope"])
	realm.Host = net.JoinHostPort(bindIP, realm.Port())
	realm.RawQuery = q.Encode()
	tokenBody, tokenCode, _, e := m.readProbeHeaders(ctx, realm.String(), origin.Host, "", "", nil)
	if e != nil || tokenCode != 200 {
		return nil, tokenCode, errors.New("registry token refused")
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(tokenBody, &token) != nil {
		return nil, tokenCode, errors.New("malformed registry token")
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" || len(token.Token) > 65536 || strings.ContainsAny(token.Token, "\r\n") {
		return nil, tokenCode, errors.New("invalid registry token")
	}
	body, code, _, e = m.readProbeHeaders(ctx, endpoint, origin.Host, "", token.Token, nil)
	return body, code, e
}

func isHTTPTransport(t http.RoundTripper) bool { _, ok := t.(*http.Transport); return ok }

func mustNormalizeRequirements(r Requirements) Requirements {
	out, _ := NormalizeRequirements(r)
	return out
}

// RequirementKey is the canonical non-secret durable consumer selection.
func RequirementKey(r Requirements) string {
	normalized, e := NormalizeRequirements(r)
	if e != nil {
		return ""
	}
	out := make([]string, len(normalized))
	for i, c := range normalized {
		out[i] = string(c)
	}
	return strings.Join(out, ",")
}
