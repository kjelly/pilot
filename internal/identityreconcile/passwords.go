package identityreconcile

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// PasswordSource gives the executor the password of a user it has to set. The
// plan never carries one (spec §7.8, I6): the value is taken here, at the moment
// of the call, for the users that have a password operation and no others.
type PasswordSource interface {
	// InitialPassword returns the password.initial of the roster user, or an
	// error that never holds a value.
	InitialPassword(user string) (string, error)
}

// rosterPasswords holds the literal passwords of a roster in memory.
type rosterPasswords struct {
	byUser map[string]inventory.RosterUserPassword // keyed by the lower-case name
}

// NewRosterPasswords reads the passwords of the plaintext roster rosterData: only
// a literal (a string Ansible uses as written) can be handed out; every other form
// is refused by name when asked for. Two names that differ only in case are
// refused: the plan blocks them (case_collision), and a password must never be
// picked between them.
func NewRosterPasswords(rosterData []byte) (PasswordSource, error) {
	all, err := inventory.RosterUserPasswords(rosterData)
	if err != nil {
		return nil, err
	}
	p := &rosterPasswords{byUser: map[string]inventory.RosterUserPassword{}}
	for name, pw := range all {
		key := strings.ToLower(name)
		if _, dup := p.byUser[key]; dup {
			return nil, fmt.Errorf("the users %q differ only in case: FreeIPA stores one name", key)
		}
		p.byUser[key] = pw
	}
	return p, nil
}

func (p *rosterPasswords) InitialPassword(user string) (string, error) {
	pw, ok := p.byUser[strings.ToLower(user)]
	if !ok {
		return "", fmt.Errorf("the roster has no user %q", user)
	}
	if pw.Form != inventory.PasswordLiteral {
		return "", fmt.Errorf("the password of %q is %s, not a string written out in the roster", user, pw.Form)
	}
	return pw.Value, nil
}

// String and GoString never show a password, in any verb.
func (p *rosterPasswords) String() string {
	return fmt.Sprintf("roster passwords (%d users)", len(p.byUser))
}
func (p *rosterPasswords) GoString() string { return p.String() }
