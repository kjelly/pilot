package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestExtractRepeatedValueFlag_MultipleOccurrencesBothForms(t *testing.T) {
	args := []string{"playbook.yml", "--group", "masters=a,b", "-e", "x=1", "--group=replicas=c"}
	out, vals := extractRepeatedValueFlag(args, "--group")
	wantOut := []string{"playbook.yml", "-e", "x=1"}
	if !reflect.DeepEqual(out, wantOut) {
		t.Errorf("out = %v, want %v", out, wantOut)
	}
	wantVals := []string{"masters=a,b", "replicas=c"}
	if !reflect.DeepEqual(vals, wantVals) {
		t.Errorf("vals = %v, want %v", vals, wantVals)
	}
}

func TestExtractRepeatedValueFlag_NoOccurrences(t *testing.T) {
	args := []string{"playbook.yml", "-e", "x=1"}
	out, vals := extractRepeatedValueFlag(args, "--group")
	if !reflect.DeepEqual(out, args) {
		t.Errorf("out = %v, want unchanged %v", out, args)
	}
	if len(vals) != 0 {
		t.Errorf("vals = %v, want empty", vals)
	}
}

func TestParseVtGroups_MultipleGroupsAndRepeatedGroupAccumulates(t *testing.T) {
	order, groups, err := parseVtGroups([]string{"masters=a,b", "replicas=c", "masters=d"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantOrder := []string{"masters", "replicas"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("order = %v, want %v", order, wantOrder)
	}
	wantMasters := []string{"a", "b", "d"}
	if !reflect.DeepEqual(groups["masters"], wantMasters) {
		t.Errorf("groups[masters] = %v, want %v", groups["masters"], wantMasters)
	}
	if !reflect.DeepEqual(groups["replicas"], []string{"c"}) {
		t.Errorf("groups[replicas] = %v, want [c]", groups["replicas"])
	}
}

func TestParseVtGroups_InvalidFormatErrors(t *testing.T) {
	cases := []string{"noequalsign", "=noname", "empty="}
	for _, v := range cases {
		if _, _, err := parseVtGroups([]string{v}); err == nil {
			t.Errorf("parseVtGroups(%q) expected an error, got none", v)
		}
	}
}

func TestBuildVtWireBlock_Format(t *testing.T) {
	block := buildVtWireBlock([][2]string{
		{"192.168.122.10", "ipa-primary"},
		{"192.168.122.11", "ipa2"},
	})
	if !strings.HasPrefix(block, vtWireMarkerBegin+"\n") {
		t.Errorf("block does not start with begin marker: %s", block)
	}
	if !strings.HasSuffix(block, vtWireMarkerEnd+"\n") {
		t.Errorf("block does not end with end marker: %s", block)
	}
	for _, want := range []string{"192.168.122.10\tipa-primary", "192.168.122.11\tipa2"} {
		if !strings.Contains(block, want) {
			t.Errorf("block missing %q, got:\n%s", want, block)
		}
	}
}

func TestExtraVarsFileArg_RecognizesAllThreeForms(t *testing.T) {
	cases := []struct {
		arg      string
		wantGlue string
		wantPath string
		wantOK   bool
	}{
		{"@/tmp/vault.yaml", "@", "/tmp/vault.yaml", true},
		{"-e@/tmp/vault.yaml", "-e@", "/tmp/vault.yaml", true},
		{"--extra-vars=@/tmp/vault.yaml", "--extra-vars=@", "/tmp/vault.yaml", true},
		{"foo=bar", "", "", false},
		{"-e", "", "", false},
		{"--extra-vars", "", "", false},
	}
	for _, tc := range cases {
		glue, path, ok := extraVarsFileArg(tc.arg)
		if ok != tc.wantOK || glue != tc.wantGlue || path != tc.wantPath {
			t.Errorf("extraVarsFileArg(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.arg, glue, path, ok, tc.wantGlue, tc.wantPath, tc.wantOK)
		}
	}
}

func TestVtWireScript_DeletesPriorBlockThenAppendsIdempotently(t *testing.T) {
	s := vtWireScript()
	if !strings.Contains(s, "sed -i") || !strings.Contains(s, "/etc/hosts") {
		t.Fatalf("expected a sed-based /etc/hosts edit, got: %s", s)
	}
	if !strings.Contains(s, "cat >> /etc/hosts") {
		t.Fatalf("expected the new block to be appended via stdin, got: %s", s)
	}
	// The delete range must reference both markers so a second wire call
	// removes exactly the block the first call wrote (no duplication).
	if !strings.Contains(s, vtWireMarkerBegin) || !strings.Contains(s, vtWireMarkerEnd) {
		t.Fatalf("expected both markers in the delete range, got: %s", s)
	}
}
