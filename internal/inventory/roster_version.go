package inventory

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// RosterSchemaVersion identifies a roster document's schema generation.
// See ValidateRosterV1/ValidateRosterV2 for what each version accepts.
type RosterSchemaVersion int

const (
	RosterSchemaV1 RosterSchemaVersion = 1
	RosterSchemaV2 RosterSchemaVersion = 2

	// CurrentRosterSchemaVersion is the version new rosters are created as
	// and the version `pilot roster migrate` upgrades existing rosters to.
	CurrentRosterSchemaVersion = RosterSchemaV2
)

// DetectRosterSchemaVersion reads the declared schema_version out of raw
// roster bytes. It does not run structural validation — a document that
// declares a version this pilot doesn't understand still detects cleanly;
// callers decide what to do with the result (ValidateRoster fails closed
// on an unsupported version, the migration engine uses this to pick which
// path to take before validating anything).
//
// data must already be plaintext: an ansible-vault-encrypted roster's
// declared version can't be read without decrypting it first, so this
// returns ErrRosterEncrypted unchanged, the same detection ValidateRosterFile
// uses.
func DetectRosterSchemaVersion(data []byte) (RosterSchemaVersion, error) {
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return 0, ErrRosterEncrypted
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return 0, fmt.Errorf("parse roster: %w", err)
	}
	raw, ok := root["schema_version"]
	if !ok {
		return 0, fmt.Errorf("schema_version is missing")
	}
	n, ok := toInt(raw)
	if !ok {
		return 0, fmt.Errorf("schema_version must be an integer, got %v", raw)
	}
	return RosterSchemaVersion(n), nil
}
