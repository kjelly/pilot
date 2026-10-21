// Package contracts provides the shipped component contracts when a command is
// editing a workspace outside the installation's contract directory.
package contracts

import "embed"

// Files is compiled from the same YAML files used by the contract loader, so
// security metadata does not require a second handwritten list of secret keys.
//
//go:embed *.yaml
var Files embed.FS
