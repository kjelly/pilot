package contract

import (
	"encoding/json"
	"math"
	"testing"
)

func TestValueMatchesType(t *testing.T) {
	cases := []struct {
		typ   string
		value any
		want  bool
	}{
		// ansible-inventory --list JSON, YAML-decoded -e, quoted group_vars.
		{"integer", float64(2514), true},
		{"integer", 2514, true},
		{"integer", "2514", true},
		{"integer", json.Number("2514"), true},
		{"integer", int64(-1), true},
		{"integer", "-1", true},
		{"integer", 14.5, false},
		{"integer", "14.5", false},
		{"integer", json.Number("14.5"), false},
		{"integer", "fourteen", false},
		{"integer", "", false},
		{"integer", " 14", false},
		{"integer", nil, false},
		{"integer", true, false},
		{"integer", []any{float64(14)}, false},
		{"integer", math.NaN(), false},
		{"integer", math.Inf(1), false},
		{"string", "/var/log/siem", true},
		{"string", float64(2514), false},
		{"duration", "15s", true},
		{"boolean", true, true},
		{"boolean", "true", false},
		{"stringList", []any{"a"}, true},
		{"stringList", []string{"a"}, true},
		{"stringList", "a", false},
		{"unknown", "a", false},
	}
	for _, tc := range cases {
		if got := ValueMatchesType(tc.typ, tc.value); got != tc.want {
			t.Errorf("ValueMatchesType(%q, %#v) = %v, want %v", tc.typ, tc.value, got, tc.want)
		}
	}
}
