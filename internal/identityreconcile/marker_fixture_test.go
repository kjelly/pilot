package identityreconcile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The marker captures of Phase 2, P2-4 (K10) were taken with the harness's own
// copy of the marker's name (internal/freeiparpc cannot import this package:
// the writer will import it). These tests hold the two copies together: the
// group the server created under that name, with that description, is the
// marker this package names and describes for the roster group the harness
// used (spec §7.9: the marker of a group is checked by its name and description
// before the group is deleted).

const captureMarkerGroup = "p24cap-gmk" // the roster group of the capture

func readCapturedMarker(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// markerFixtureProblems says where a captured answer (add, show, or the first
// entry of a find) disagrees with HistoryMarkerName and
// HistoryMarkerDescription for group.
func markerFixtureProblems(raw []byte, group string, find bool) []string {
	var doc struct {
		Result struct {
			Result json.RawMessage `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"not an answer: " + err.Error()}
	}
	var entries []map[string]any
	if find {
		if err := json.Unmarshal(doc.Result.Result, &entries); err != nil || len(entries) != 1 {
			return []string{"a find that did not return exactly one group"}
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(doc.Result.Result, &one); err != nil {
			return []string{"no entry in the result"}
		}
		entries = []map[string]any{one}
	}
	// the values of the list-valued attributes (dn is a plain string)
	entry := map[string][]string{}
	for k, v := range entries[0] {
		if l, ok := v.([]any); ok {
			for _, e := range l {
				if s, ok := e.(string); ok {
					entry[k] = append(entry[k], s)
				}
			}
		}
	}
	var problems []string
	if !slices.Equal(entry["cn"], []string{HistoryMarkerName(group)}) {
		problems = append(problems, "cn is not HistoryMarkerName of the roster group")
	}
	if !slices.Equal(entry["description"], []string{HistoryMarkerDescription(group)}) {
		problems = append(problems, "description is not HistoryMarkerDescription of the roster group")
	}
	return problems
}

func TestCapturedMarkerIsTheMarkerThisPackageNames(t *testing.T) {
	for name, find := range map[string]bool{"group-add-marker": false, "group-show-marker": false, "group-find-marker": true} {
		if got := markerFixtureProblems(readCapturedMarker(t, name), captureMarkerGroup, find); len(got) != 0 {
			t.Errorf("%s: %v", name, got)
		}
	}
	// the capture of a marker whose description was changed is the case this
	// check has to refuse
	if got := markerFixtureProblems(readCapturedMarker(t, "group-show-marker-changed"), captureMarkerGroup, false); len(got) != 1 || !strings.Contains(got[0], "description") {
		t.Errorf("a marker with another description: %v, want the description refused and the name accepted", got)
	}
}

// The check fires on each way the two copies could part.
func TestMarkerFixtureCheckFires(t *testing.T) {
	good := string(readCapturedMarker(t, "group-show-marker"))
	for name, tc := range map[string]struct {
		change func(string) string
		group  string
		want   string
	}{
		"another roster group": {func(s string) string { return s }, "p24cap-other", "cn is not"},
		"a changed name": {func(s string) string {
			return strings.Replace(s, "pilot-internal-history-g-", "pilot-internal-history-x-", 1)
		}, captureMarkerGroup, "cn is not"},
		"a changed description":       {func(s string) string { return strings.Replace(s, "name=p24cap-gmk", "name=p24cap-gmx", 1) }, captureMarkerGroup, "description is not"},
		"a description prefix change": {func(s string) string { return strings.Replace(s, "group-history/v1", "group-history/v2", 1) }, captureMarkerGroup, "description is not"},
	} {
		t.Run(name, func(t *testing.T) {
			got := markerFixtureProblems([]byte(tc.change(good)), tc.group, false)
			if len(got) == 0 || !strings.Contains(strings.Join(got, ";"), tc.want) {
				t.Fatalf("problems = %v, want one with %q", got, tc.want)
			}
		})
	}
}
