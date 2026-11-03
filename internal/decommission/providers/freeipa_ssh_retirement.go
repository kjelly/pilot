package providers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// A dedicated versioned envelope keeps generic same-host tombstone inspection
// out of the retirement result. Base64 avoids callback JSON quote escaping.
var sshRetirementResponse = regexp.MustCompile(`PILOT_SSH_RETIREMENT_V1:([^\s"\\]+)`)

type sshRetirementObservation struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	FQDN          string `json:"fqdn"`
	Alias         string `json:"alias"`
	Stage         string `json:"stage"`
	Status        string `json:"status"`
}

func retirementObservation(stdout, fqdn, alias, stage string) (bool, error) {
	matches := sshRetirementResponse.FindAllStringSubmatch(stdout, -1)
	if len(matches) != 1 || strings.Count(stdout, "PILOT_SSH_RETIREMENT_V1:") != 1 {
		return false, fmt.Errorf("SSH retirement requires exactly one typed observation")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(matches[0][1])
	if err != nil {
		return false, fmt.Errorf("invalid SSH retirement observation encoding")
	}
	// JSON's normal struct decoder accepts repeated and case-insensitive
	// field names. This protocol requires the exact six fields once each.
	fields := json.NewDecoder(strings.NewReader(string(payload)))
	if token, err := fields.Token(); err != nil || token != json.Delim('{') {
		return false, fmt.Errorf("invalid SSH retirement observation object")
	}
	seen := map[string]bool{}
	for fields.More() {
		token, err := fields.Token()
		name, named := token.(string)
		if err != nil || !named || seen[name] ||
			(name != "schema_version" && name != "kind" && name != "fqdn" && name != "alias" && name != "stage" && name != "status") {
			return false, fmt.Errorf("invalid SSH retirement observation field set")
		}
		seen[name] = true
		if err := fields.Decode(new(json.RawMessage)); err != nil {
			return false, fmt.Errorf("invalid SSH retirement observation field value")
		}
	}
	if len(seen) != 6 {
		return false, fmt.Errorf("missing SSH retirement observation field")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var observation sshRetirementObservation
	if err := decoder.Decode(&observation); err != nil {
		return false, fmt.Errorf("invalid SSH retirement observation fields")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, fmt.Errorf("invalid SSH retirement observation trailing data")
	}
	if observation.SchemaVersion != 1 || observation.Kind != "ssh_retirement" ||
		observation.FQDN != strings.ToLower(strings.TrimSuffix(fqdn, ".")) ||
		observation.Alias != alias || alias == "" || observation.Stage != stage ||
		(observation.Status != "pending" && observation.Status != "settled") {
		return false, fmt.Errorf("SSH retirement observation does not match the exact request")
	}
	return observation.Status == "settled", nil
}
