// Package evidence produces the machine-generated part of an actual-run
// evidence record (AGENTS.md §1.2, docs/actual-run-evidence.md): the tested
// candidate, the execution closure of the playbooks that ran with Git blob
// ids the gates can compare against HEAD, the PLAY RECAP and verify numbers
// of every step, the targets, and a redaction scan of the captured output.
// The operator adds only the prose the tool cannot know: which failure-path
// arms were run and what the run does not prove.
package evidence

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// GitBlobOID is the object id Git gives a blob with this content
// (sha1 over "blob <len>\0<content>"), so a record written from a `git
// archive` copy, where no .git exists, still names ids that `git ls-tree`
// at the tested commit and at HEAD report.
func GitBlobOID(content []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// SHA256Hex is the hex SHA-256 of content.
func SHA256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// SHA256File streams a file through SHA-256 (base images are gigabytes).
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
