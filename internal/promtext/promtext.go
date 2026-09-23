// Package promtext renders a small set of counters and gauges in the
// Prometheus text exposition format and writes them atomically for the
// node_exporter textfile collector (per-host recording spec §31). It
// mirrors internal/detection's textfile writer without pulling in
// client_golang or opening a TCP listener.
package promtext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry holds metric families in registration order.
type Registry struct {
	mu       sync.Mutex
	families []*family
}

type family struct {
	name, help, kind string
	labels           []string
	values           map[string]float64 // key: label values joined by \x00
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Vec is a counter or gauge family with fixed label names.
type Vec struct {
	r *Registry
	f *family
}

// Counter registers a counter family.
func (r *Registry) Counter(name, help string, labels ...string) *Vec {
	return r.register(name, help, "counter", labels)
}

// Gauge registers a gauge family.
func (r *Registry) Gauge(name, help string, labels ...string) *Vec {
	return r.register(name, help, "gauge", labels)
}

func (r *Registry) register(name, help, kind string, labels []string) *Vec {
	f := &family{name: name, help: help, kind: kind, labels: labels, values: map[string]float64{}}
	r.mu.Lock()
	r.families = append(r.families, f)
	r.mu.Unlock()
	return &Vec{r: r, f: f}
}

func (v *Vec) key(labelValues []string) string {
	if len(labelValues) != len(v.f.labels) {
		panic(fmt.Sprintf("promtext: %s takes %d label values, got %d", v.f.name, len(v.f.labels), len(labelValues)))
	}
	return strings.Join(labelValues, "\x00")
}

// Add adds delta to the series with labelValues.
func (v *Vec) Add(delta float64, labelValues ...string) {
	k := v.key(labelValues)
	v.r.mu.Lock()
	v.f.values[k] += delta
	v.r.mu.Unlock()
}

// Inc adds one to the series with labelValues.
func (v *Vec) Inc(labelValues ...string) { v.Add(1, labelValues...) }

// Set sets the series with labelValues to value.
func (v *Vec) Set(value float64, labelValues ...string) {
	k := v.key(labelValues)
	v.r.mu.Lock()
	v.f.values[k] = value
	v.r.mu.Unlock()
}

// Value returns the current value of the series with labelValues.
func (v *Vec) Value(labelValues ...string) float64 {
	k := v.key(labelValues)
	v.r.mu.Lock()
	defer v.r.mu.Unlock()
	return v.f.values[k]
}

// Render returns every family in text exposition format. HELP and TYPE are
// always written, so a family with no series yet is still discoverable;
// series are sorted for a stable file.
func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, f := range r.families {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.name, escapeHelp(f.help), f.name, f.kind)
		keys := make([]string, 0, len(f.values))
		for k := range f.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(f.name)
			if len(f.labels) > 0 {
				values := strings.Split(k, "\x00")
				b.WriteByte('{')
				for i, name := range f.labels {
					if i > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, "%s=\"%s\"", name, escapeLabel(values[i]))
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(strconv.FormatFloat(f.values[k], 'g', -1, 64))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

// WriteTextfile atomically replaces path with the rendered registry, mode
// 0644 so node_exporter (another user) can read it.
func (r *Registry) WriteTextfile(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*.prom.tmp")
	if err != nil {
		return fmt.Errorf("create metrics temp file: %w", err)
	}
	tmpPath := tmp.Name()
	fail := func(step string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%s metrics temp file: %w", step, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return fail("chmod", err)
	}
	if _, err := tmp.WriteString(r.Render()); err != nil {
		return fail("write", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close metrics temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename metrics file: %w", err)
	}
	return nil
}

// WriteLoop writes path immediately, then every interval, and once more
// when ctx ends. Before each write it sets lastWrite (a label-less gauge,
// may be nil) to the current Unix time. Write errors go to onError and
// never stop the loop: metrics are not essential to the service.
func (r *Registry) WriteLoop(ctx context.Context, path string, interval time.Duration, lastWrite *Vec, onError func(error)) {
	write := func() {
		if lastWrite != nil {
			lastWrite.Set(float64(time.Now().Unix()))
		}
		if err := r.WriteTextfile(path); err != nil && onError != nil {
			onError(err)
		}
	}
	write()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			write()
		case <-ctx.Done():
			write()
			return
		}
	}
}

// StartWriter runs WriteLoop in the background and returns a func that
// stops it after one final write.
func (r *Registry) StartWriter(path string, interval time.Duration, lastWrite *Vec, onError func(error)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.WriteLoop(ctx, path, interval, lastWrite, onError)
	}()
	return func() {
		cancel()
		<-done
	}
}
