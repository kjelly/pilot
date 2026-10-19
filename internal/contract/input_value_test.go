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
		{"stringOrStringList", "1.1.1.1 port 53 9.9.9.9", true},
		{"stringOrStringList", "", true},
		{"stringOrStringList", nil, true},
		{"stringOrStringList", []string{"1.1.1.1"}, true},
		{"stringOrStringList", []any{"1.1.1.1", "9.9.9.9 port 53"}, true},
		{"stringOrStringList", []any{}, true},
		{"stringOrStringList", []any{float64(1)}, false},
		{"stringOrStringList", []any{nil}, false},
		{"stringOrStringList", true, false},
		{"stringOrStringList", float64(1), false},
		{"stringOrStringList", map[string]any{"address": "1.1.1.1"}, false},
		{"unknown", "a", false},
	}
	for _, tc := range cases {
		if got := ValueMatchesType(tc.typ, tc.value); got != tc.want {
			t.Errorf("ValueMatchesType(%q, %#v) = %v, want %v", tc.typ, tc.value, got, tc.want)
		}
	}
}

func TestStringOrStringListDefaults(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  bool
	}{
		{nil, true}, {"", true}, {"1.1.1.1", true},
		{[]string{"1.1.1.1"}, true}, {[]any{"1.1.1.1"}, true},
		{[]any{}, true}, {true, false}, {[]any{53}, false},
	} {
		err := validateGroupVars([]GroupVar{{Name: "forwarders", Type: "stringOrStringList", Default: tc.value}}, nil)
		if (err == nil) != tc.want {
			t.Errorf("default %#v: error=%v, want valid=%v", tc.value, err, tc.want)
		}
	}
}
