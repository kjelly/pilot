// Package generated exposes version-controlled SNMP module assets that pilot
// edit can bootstrap into a separate configuration workspace.  The assets
// remain ordinary files in this directory so their provenance is reviewable.
package generated

import _ "embed"

// IFMIB is the official snmp-exporter v0.30.1 if_mib module committed beside
// this source file.  It is generated during development, never on a managed
// production host.
//
//go:embed if_mib.yml
var IFMIB []byte
