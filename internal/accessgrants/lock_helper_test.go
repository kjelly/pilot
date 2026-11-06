package accessgrants

import (
	"testing"

	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// testLock is the lock a funnel's test hands it: the funnels refuse to run
// without one (identitylock.ErrNoLock), and a test of a refusal that did not
// hand one would pass for that reason and prove nothing about its own gate.
// The tests of the lock itself (lock_test.go) use identitylocktest.Fake
// directly, to see when it is taken and given back.
func testLock(t *testing.T) identitylock.Acquirer {
	t.Helper()
	return (&identitylocktest.Fake{}).Acquirer()
}
