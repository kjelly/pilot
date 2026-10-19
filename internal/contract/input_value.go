package contract

import (
	"encoding/json"
	"math"
	"regexp"
)

// decimalInteger matches a quoted whole number, such as `port: "2514"`.
var decimalInteger = regexp.MustCompile(`^[+-]?[0-9]+$`)

// ValueMatchesType reports whether a resolved inventory or extra-var value
// fits a groupVar type, in every form the same value reaches Pilot:
// `ansible-inventory --list` JSON decodes every number to float64, a
// YAML-decoded `-e key=2514` is an int, and a quoted `"2514"` in group_vars
// is a string. Ansible renders all three the same way into a template, so
// an integer is accepted as an int, a whole float, a json.Number or a
// decimal string. stringOrStringList preserves scalar, list and explicit-null
// inputs used by FreeIPA forwarders; required-input checks still reject null.
// Other types keep their existing Go forms.
func ValueMatchesType(typ string, value any) bool {
	switch typ {
	case "string", "duration":
		_, ok := value.(string)
		return ok
	case "stringList":
		switch value.(type) {
		case []string, []any:
			return true
		}
		return false
	case "stringOrStringList":
		switch v := value.(type) {
		case nil, string, []string:
			return true
		case []any:
			for _, item := range v {
				if _, ok := item.(string); !ok {
					return false
				}
			}
			return true
		}
		return false
	case "integer":
		return isInteger(value)
	case "boolean":
		_, ok := value.(bool)
		return ok
	default:
		return false
	}
}

func isInteger(value any) bool {
	switch v := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return wholeFloat(v)
	case float32:
		return wholeFloat(float64(v))
	case json.Number:
		_, err := v.Int64()
		return err == nil
	case string:
		return decimalInteger.MatchString(v)
	default:
		return false
	}
}

func wholeFloat(v float64) bool {
	return !math.IsInf(v, 0) && !math.IsNaN(v) && v == math.Trunc(v) && math.Abs(v) <= 1<<53
}
