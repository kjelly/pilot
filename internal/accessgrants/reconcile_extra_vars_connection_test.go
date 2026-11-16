package accessgrants

import (
	"reflect"
	"strings"
	"testing"
)

// applyPlan hands ansible-playbook `-e @<JSON of buildExtraVars>` and nothing
// else that could change where it connects. The identity lock is taken on the
// host the inventory and the -e arguments the funnel declares resolve to
// (cmd/pilot/cmd identityLockRequest.ExtraArgs); the funnels that run applyPlan
// declare none because of this: every key this JSON can carry is the roster path
// or a compiled plan section. A new field with another name (target_group,
// ansible_host, ...) would retarget the playbook behind a lock taken elsewhere
// (issue #319), so it has to be a decision made here and in the funnels.
func TestExtraVarsCarryNoConnectionSetting(t *testing.T) {
	typ := reflect.TypeOf(extraVars{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name == "" {
			t.Errorf("%s has no json name: its key would be the field name", typ.Field(i).Name)
			continue
		}
		if name != "freeipa_roster_file" && !strings.HasPrefix(name, "pilot_compiled_") {
			t.Errorf("extraVars.%s is the extra var %q: applyPlan hands it to the identity playbook under a lock taken without it; add it to the lock request of the funnels (identityLockRequest.ExtraArgs) before allowing it here", typ.Field(i).Name, name)
		}
	}
}
