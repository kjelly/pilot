package identityreconcile

// SpecRowKinds maps each users/groups row of
// docs/verification/freeipa-identity.md to the operation kinds that make it
// true and the FreeIPA attributes that verify it (spec §10.2). The
// users/groups rows are those the freeipa-identity contract traces to the
// users or groups tags.
var SpecRowKinds = map[string]struct {
	Kinds  []string
	Verify []string
}{
	"C9":  {Kinds: []string{KindUserCreate, KindUserUpdate}, Verify: []string{"displayname", "mail", "loginshell", "homedirectory"}},
	"C10": {Kinds: []string{KindUserEnable, KindUserDisable}, Verify: []string{"nsaccountlock"}},
	"C11": {Kinds: []string{KindGroupCreate, KindMemberUserAdd}, Verify: []string{"member_user"}},
	"C12": {Kinds: []string{KindMemberGroupAdd}, Verify: []string{"member_group"}},
}

// SpecRowsExempt are users/groups rows this engine never makes true.
var SpecRowsExempt = map[string]string{
	"C1": "legacy (schema-less) roster row; the Go engine refuses legacy rosters",
	"C2": "legacy (schema-less) roster row; the Go engine refuses legacy rosters",
	"C8": "legacy (schema-less) roster row; the Go engine refuses legacy rosters",
}

// KindsWithoutSpecRow are operation kinds no checklist row verifies yet.
// Once a row does, its entry here is stale and the check fails.
var KindsWithoutSpecRow = map[string]string{
	KindGroupUpdate:        "group description drift has no checklist row",
	KindMarkerCreate:       "history markers are candidate row C25, outside the parsed §2 checklist",
	KindPasswordInitialize: "passwords are verified by the manual §7.4 procedure",
	KindPasswordReset:      "passwords are verified by the manual §7.4 procedure",
	KindMemberUserRemove:   "revocation has no checklist row; §7.3 is a manual procedure",
	KindMemberGroupRemove:  "revocation has no checklist row; §7.3 is a manual procedure",
	KindUserDelete:         "user deletion has no checklist row",
	KindGroupDelete:        "group deletion is candidate row C26, outside the parsed §2 checklist",
}
