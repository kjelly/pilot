package contract

import (
	"strings"
	"testing"
)

func TestManagedProviderApplyRequiresExplicitRequiredEndpoint(t *testing.T) {
	for _, tc := range []struct {
		relation               string
		required, flag, reject bool
	}{
		{"providerEndpoint", true, true, false},
		{"providerEndpoint", true, false, false},
		{"providerEndpoint", false, true, true},
		{"sameHosts", true, true, true},
		{"planOnly", true, true, true},
	} {
		t.Run(tc.relation+"-"+map[bool]string{true: "required", false: "optional"}[tc.required]+"-"+map[bool]string{true: "auto", false: "bound"}[tc.flag], func(t *testing.T) {
			c := minimalValidContract()
			c.Dependencies = []Dependency{{Component: "provider", Relation: tc.relation, Required: tc.required, ApplyBeforeConsumer: tc.flag}}
			c.GroupVars = []GroupVar{{Name: "provider_host", Type: "string"}}
			c.Bindings = []Binding{{Input: "provider_host", SourceSelection: "exactlyOne", From: BindingFrom{Component: "provider", Endpoint: "api"}}}
			err := validateLocal(c)
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "applyBeforeConsumer requires") {
					t.Fatalf("wanted policy rejection, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
