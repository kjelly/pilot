package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverAnnotationCRUD(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_annotation", Host: "web-1", Key: "location", Value: "DC1"},
			{Action: "add_annotation", Host: "web-1", Key: "project", Value: "alpha"},
			{Action: "edit_annotation", Host: "web-1", Key: "location", Value: "DC2"},
			{Action: "delete_annotation", Host: "web-1", Key: "project"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want 1 host", hf.Hosts)
	}
	annotations := hf.Hosts[0].Annotations
	if len(annotations) != 1 || annotations["location"] != "DC2" {
		t.Fatalf("annotations = %+v, want exactly location=DC2", annotations)
	}
	if _, ok := hf.Hosts[0].Extra["location"]; ok {
		t.Fatalf("annotation leaked into Extra: %+v", hf.Hosts[0].Extra)
	}
}

// TestEditAutomationDriverExtraVarActionDoesNotTouchAnnotations is the
// mirror of TestEditAutomationDriverAnnotationCRUD's own "doesn't leak into
// Extra" assertion (spec.md §24): the two CRUD flows share UI shape but
// write to genuinely separate Host maps, in both directions.
func TestEditAutomationDriverExtraVarActionDoesNotTouchAnnotations(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "location", Value: "not-an-annotation"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if got := hf.Hosts[0].Extra["location"]; got != "not-an-annotation" {
		t.Fatalf("Extra[location] = %q, want not-an-annotation", got)
	}
	if _, ok := hf.Hosts[0].Annotations["location"]; ok {
		t.Fatalf("extra var leaked into Annotations: %+v", hf.Hosts[0].Annotations)
	}
}

// TestEditAutomationDriverAddAnnotationDuplicateKeyErrors mirrors
// TestEditAutomationDriverAddExtraVarDuplicateKeyErrors: pushAddAnnotation's
// validate() (edit_tui_annotations.go) rejects a key that already exists in
// h.Annotations, and the driver must surface that message rather than the
// opaque screen-type-mismatch error a rejected Enter used to produce.
func TestEditAutomationDriverAddAnnotationDuplicateKeyErrors(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_annotation", Host: "web-1", Key: "project", Value: "alpha"},
			{Action: "add_annotation", Host: "web-1", Key: "project", Value: "beta"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error naming the duplicate key")
	}
	if strings.Contains(err.Error(), "cannot choose") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "已存在") {
		t.Fatalf("driver.run() error = %v, want it to say the key already exists", err)
	}
}

// TestEditAutomationDriverAddAnnotationOverMaxCountRejectedByTUIValidate
// proves the per-host count ceiling (spec.md §4.7, inventory.
// MaxAnnotationsPerHost) is enforced by pushAddAnnotation's runtime
// validate() against the host's *live* Annotations map — something the
// registry-level validateAddOrEditAnnotation cannot see, since it only
// validates one step in isolation, not the accumulated state a prior
// scenario step's add_annotation calls built up. Each individual step here
// passes registry-level validation on its own; only the 33rd add actually
// fails, at TUI-validate time.
func TestEditAutomationDriverAddAnnotationOverMaxCountRejectedByTUIValidate(t *testing.T) {
	dir := t.TempDir()
	steps := []editAction{{Action: "create_host", Host: "web-1"}}
	for i := 0; i <= inventory.MaxAnnotationsPerHost; i++ {
		steps = append(steps, editAction{Action: "add_annotation", Host: "web-1", Key: fmt.Sprintf("k%02d", i), Value: "v"})
	}
	scenario := editScenario{Version: 1, Steps: steps}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error about the per-host annotation count limit")
	}
	if strings.Contains(err.Error(), "cannot choose") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "上限") {
		t.Fatalf("driver.run() error = %v, want it to mention the per-host limit", err)
	}
}
