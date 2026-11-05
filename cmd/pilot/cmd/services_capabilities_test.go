package cmd

import (
	"github.com/kjelly/pilot/internal/services"
	"github.com/kjelly/pilot/internal/vmtarget"
	"reflect"
	"testing"
)

func TestVMServiceCapabilityFlagAndTopologyRouting(t *testing.T) {
	flag := vtUpCmd.Flags().Lookup("service-capabilities")
	if flag == nil || flag.DefValue != "" {
		t.Fatal("explicit capability flag or conservative omitted default missing")
	}
	spec := &vmtarget.TopologySpec{ServiceCapabilities: services.Requirements{services.APT}, Nodes: []vmtarget.TopologyNode{{Name: "apt"}, {Name: "oci", ServiceCapabilities: services.Requirements{services.OCI}}}}
	shared := &vmtarget.ServiceBootstrap{Requirements: services.Requirements{services.APT, services.OCI}}
	a := serviceBootstrapForNode(shared, spec, spec.Nodes[0])
	b := serviceBootstrapForNode(shared, spec, spec.Nodes[1])
	if !reflect.DeepEqual(a.Requirements, services.Requirements{services.APT}) || !reflect.DeepEqual(b.Requirements, services.Requirements{services.OCI}) || !reflect.DeepEqual(shared.Requirements, services.Requirements{services.APT, services.OCI}) {
		t.Fatal("mixed topology broadened node scope or changed shared preflight contract")
	}
}
