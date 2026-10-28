package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// ErrRosterChanged is returned by RestoreRosterFile and RemoveRosterFile
// when the roster no longer holds the bytes the caller's session left
// there: another writer changed it since, so putting the old bytes back
// would lose that change.
var ErrRosterChanged = errors.New("inventory: roster changed since this session wrote it")

// RestoreRosterFile puts original back into the roster at path — pilot
// edit's apply rollback — under the roster's lock and only while the
// roster still holds expected, the bytes the rolling-back session left
// there. `pilot roster`, `pilot access` and decommission write rosters
// without pilot edit's workspace lock, so between the session's write and
// the rollback one of them may have read the session's roster and saved
// on top of it; restoring then would undo their change (PR #148
// re-review). A roster already holding original — restored through
// another of its names, say — is done. Held (ErrMutationLocked), unusable
// lock file (ErrRosterLockFile) or changed (ErrRosterChanged): nothing is
// written, and the caller reports the roster for a hand check.
func RestoreRosterFile(path string, expected, original []byte) error {
	lk, err := lockRosterFile(path)
	if err != nil {
		return err
	}
	defer lk.release() //nolint:errcheck
	if current, err := readSecretSourceFile(lk.target); err == nil && bytes.Equal(current, original) {
		return nil
	}
	if err := rosterStillHolds(lk, expected); err != nil {
		return err
	}
	return writeLockedRoster(lk, original)
}

// RemoveRosterFile is RestoreRosterFile for a roster the session created:
// path is removed, on the same conditions.
func RemoveRosterFile(path string, expected []byte) error {
	lk, err := lockRosterFile(path)
	if err != nil {
		return err
	}
	defer lk.release() //nolint:errcheck
	if err := rosterStillHolds(lk, expected); err != nil {
		return err
	}
	return os.Remove(lk.path)
}

// HoldRosterLock takes the roster lock on the file path names, for a writer
// outside this package that hands the roster to another program — pilot
// edit's `ansible-vault edit` of an encrypted .vault/ file — and returns
// the release to call once that program is done. The errors are
// lockRosterFile's: ErrMutationLocked, ErrRosterLockFile, and
// ErrRosterNotWritable for a file this user may not write.
func HoldRosterLock(path string) (release func() error, err error) {
	lk, err := lockRosterFile(path)
	if err != nil {
		return nil, err
	}
	return lk.release, nil
}

func rosterStillHolds(lk *rosterLock, expected []byte) error {
	current, err := readSecretSourceFile(lk.target)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("roster %s: %w", lk.path, ErrRosterChanged)
	}
	return nil
}
