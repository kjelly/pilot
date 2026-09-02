package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SampleValidity is the per-(pilot_host,site,feature) classification
// implemented by spec §13.
type SampleValidity string

const (
	ValidityValid           SampleValidity = "valid"
	ValidityMissing         SampleValidity = "missing"
	ValidityAmbiguousSeries SampleValidity = "ambiguous_series"
	ValidityNonFinite       SampleValidity = "non_finite"
	ValidityFutureSample    SampleValidity = "future_sample"
	ValidityStale           SampleValidity = "stale"
	ValidityOutOfRange      SampleValidity = "out_of_range"
)

// RawSample is one Prometheus-compatible instant-query sample for a single
// logical subject key, already extracted from the JSON response.
type RawSample struct {
	Timestamp int64 // unix seconds
	Value     float64
}

// ClassifySample implements spec §13's normalization table for one
// (subject, site, feature) key given however many raw samples the query
// returned for it this cycle. maxSampleAge/futureSkewTolerance come from
// the feature profile's own SamplingProfile (spec §9.3) — no longer a
// single global constant, since a non-Linux-host profile's natural PromQL
// staleness may differ.
func ClassifySample(samples []RawSample, evaluationTime int64, feature Feature, maxSampleAge, futureSkewTolerance time.Duration) (float64, SampleValidity) {
	switch len(samples) {
	case 0:
		return 0, ValidityMissing
	case 1:
		s := samples[0]
		// NaN/Inf must be checked before range comparisons: NaN < min and
		// NaN > max are both false in IEEE 754, so checking range first
		// would silently misclassify a non-finite sample as in-range.
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			return s.Value, ValidityNonFinite
		}
		if s.Timestamp > evaluationTime+int64(futureSkewTolerance.Seconds()) {
			return s.Value, ValidityFutureSample
		}
		if evaluationTime-s.Timestamp > int64(maxSampleAge.Seconds()) {
			return s.Value, ValidityStale
		}
		if s.Value < feature.ValidMin || s.Value > feature.ValidMax {
			return s.Value, ValidityOutOfRange
		}
		return s.Value, ValidityValid
	default:
		return 0, ValidityAmbiguousSeries
	}
}

// FeatureSampleResult is one feature's classified reading for a host this
// cycle.
type FeatureSampleResult struct {
	Feature  string
	Value    float64
	Validity SampleValidity
}

// HostCycleValid implements spec §13's aggregate rule: any required
// feature that is invalid (or entirely missing from the result map)
// invalidates the whole host cycle; an invalid/missing optional feature
// does not.
func HostCycleValid(profile FeatureProfile, results map[string]FeatureSampleResult) bool {
	for _, f := range profile.RequiredFeatures() {
		r, ok := results[f.Name]
		if !ok || r.Validity != ValidityValid {
			return false
		}
	}
	return true
}

// ValidCurrentValues extracts the features that classified as valid this
// cycle — the exact map shape ComputeBaselineHostScore/ComputeCohortHostScore
// expect as "current" (invalid/missing features are excluded, never
// zero-filled).
func ValidCurrentValues(results map[string]FeatureSampleResult) map[string]float64 {
	out := make(map[string]float64, len(results))
	for name, r := range results {
		if r.Validity == ValidityValid {
			out[name] = r.Value
		}
	}
	return out
}

// SeriesKey identifies one detection subject at one Thanos query layer
// (spec §13's logical key). PilotHost holds the subject's ID under
// whichever identity label the active FeatureProfile configured (spec
// §9.2/§9.3) — for the default managed-host profile that is literally the
// `pilot_host` label value, but for e.g. an SNMP profile it holds the
// Monitoring Target Registry name instead. The field keeps its historical
// name because within one Engine/RunCycle call every subject shares the
// same profile-fixed Kind (Engine.Profile.EffectiveIdentity().Kind), so
// Kind never needs to vary per-key here — callers that persist or label a
// subject read Kind from the profile, not from SeriesKey.
type SeriesKey struct {
	PilotHost string
	Site      string
}

// GroupSamplesByKey buckets raw metric/value pairs from one query result by
// the profile's identity label (spec §9.2/§9.4), so ClassifySample can see
// how many series (0, 1, or >1) matched each logical key. It also returns
// each key's cohort membership, read directly from identity.CohortLabel
// when the profile configures one (spec §9.6: SNMP cohort membership is
// compiler-controlled metadata on the sample itself, never a static
// managed-host-style lookup table).
//
// A series whose identity label is empty can never be attributed to any
// subject (spec §9.4 rule 1, "missing_identity") and is dropped. A series
// whose site label is empty is dropped too for any non-managed-host kind
// (spec §9.4 rule 2 — empty site is only tolerated for legacy managed-host
// compatibility).
func GroupSamplesByKey(metrics []map[string]string, samples []RawSample, identity IdentityProfile) (map[SeriesKey][]RawSample, map[SeriesKey]string) {
	out := map[SeriesKey][]RawSample{}
	cohorts := map[SeriesKey]string{}
	for i, m := range metrics {
		id := m[identity.Label]
		if id == "" {
			continue
		}
		site := m[identity.SiteLabel]
		if site == "" && identity.Kind != SubjectKindManagedHost {
			continue
		}
		key := SeriesKey{PilotHost: id, Site: site}
		out[key] = append(out[key], samples[i])
		if identity.CohortLabel != "" {
			if c := m[identity.CohortLabel]; c != "" {
				cohorts[key] = c
			}
		}
	}
	return out, cohorts
}

// ThanosClient queries a Prometheus-compatible instant/range API — the
// Detection-facing Thanos Query endpoint (spec §10: always :10912, never
// the Sidecar's container-internal :10902).
type ThanosClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewThanosClient returns a client bound to baseURL (e.g.
// "http://10.0.0.5:10912") with the given per-request timeout (spec §11:
// query_timeout = 5s in production).
func NewThanosClient(baseURL string, timeout time.Duration) *ThanosClient {
	return &ThanosClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: timeout},
	}
}

type promAPIResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type promVectorResult struct {
	Metric map[string]string `json:"metric"`
	Value  [2]interface{}    `json:"value"`
}

type promMatrixResult struct {
	Metric map[string]string `json:"metric"`
	Values [][2]interface{}  `json:"values"`
}

func parsePromValue(raw [2]interface{}) (RawSample, error) {
	ts, ok := raw[0].(float64)
	if !ok {
		return RawSample{}, fmt.Errorf("prometheus sample: unexpected timestamp type %T", raw[0])
	}
	valStr, ok := raw[1].(string)
	if !ok {
		return RawSample{}, fmt.Errorf("prometheus sample: unexpected value type %T", raw[1])
	}
	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		// "NaN"/"+Inf"/"-Inf" all parse fine via ParseFloat; anything else
		// genuinely malformed is a real error, not a non_finite sample.
		return RawSample{}, fmt.Errorf("prometheus sample: parse value %q: %w", valStr, err)
	}
	return RawSample{Timestamp: int64(ts), Value: val}, nil
}

func (c *ThanosClient) doQuery(ctx context.Context, path string, params url.Values) (promAPIResponse, error) {
	u := c.BaseURL + path + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return promAPIResponse{}, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return promAPIResponse{}, fmt.Errorf("thanos query request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return promAPIResponse{}, fmt.Errorf("read thanos query response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return promAPIResponse{}, fmt.Errorf("thanos query http %d: %s", resp.StatusCode, string(body))
	}
	var out promAPIResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return promAPIResponse{}, fmt.Errorf("decode thanos query response: %w", err)
	}
	if out.Status != "success" {
		return promAPIResponse{}, fmt.Errorf("thanos query failed: %s: %s", out.ErrorType, out.Error)
	}
	return out, nil
}

// InstantQuery runs GET /api/v1/query at the given evaluation time (unix
// seconds) and returns one metric-labels/sample pair per matched series.
func (c *ThanosClient) InstantQuery(ctx context.Context, promql string, at int64) ([]map[string]string, []RawSample, error) {
	params := url.Values{"query": {promql}, "time": {strconv.FormatInt(at, 10)}}
	resp, err := c.doQuery(ctx, "/api/v1/query", params)
	if err != nil {
		return nil, nil, err
	}
	if resp.Data.ResultType != "vector" {
		return nil, nil, fmt.Errorf("thanos query: unexpected resultType %q (want vector)", resp.Data.ResultType)
	}
	var results []promVectorResult
	if err := json.Unmarshal(resp.Data.Result, &results); err != nil {
		return nil, nil, fmt.Errorf("decode vector result: %w", err)
	}
	metrics := make([]map[string]string, 0, len(results))
	samples := make([]RawSample, 0, len(results))
	for _, r := range results {
		sample, err := parsePromValue(r.Value)
		if err != nil {
			return nil, nil, err
		}
		metrics = append(metrics, r.Metric)
		samples = append(samples, sample)
	}
	return metrics, samples, nil
}

// RangeSeries is one (pilot_host, site)-identifying series' worth of
// historical samples, as returned by RangeQuery.
type RangeSeries struct {
	Metric  map[string]string
	Samples []RawSample
}

// RangeQuery runs GET /api/v1/query_range — used for baseline bootstrap
// (spec §14.1: 24h lookback, 60s step).
func (c *ThanosClient) RangeQuery(ctx context.Context, promql string, start, end, step int64) ([]RangeSeries, error) {
	params := url.Values{
		"query": {promql},
		"start": {strconv.FormatInt(start, 10)},
		"end":   {strconv.FormatInt(end, 10)},
		"step":  {strconv.FormatInt(step, 10)},
	}
	resp, err := c.doQuery(ctx, "/api/v1/query_range", params)
	if err != nil {
		return nil, err
	}
	if resp.Data.ResultType != "matrix" {
		return nil, fmt.Errorf("thanos range query: unexpected resultType %q (want matrix)", resp.Data.ResultType)
	}
	var results []promMatrixResult
	if err := json.Unmarshal(resp.Data.Result, &results); err != nil {
		return nil, fmt.Errorf("decode matrix result: %w", err)
	}
	out := make([]RangeSeries, 0, len(results))
	for _, r := range results {
		samples := make([]RawSample, 0, len(r.Values))
		for _, v := range r.Values {
			sample, err := parsePromValue(v)
			if err != nil {
				return nil, err
			}
			samples = append(samples, sample)
		}
		out = append(out, RangeSeries{Metric: r.Metric, Samples: samples})
	}
	return out, nil
}
