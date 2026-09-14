package freeipaaccess

import (
	"errors"
	"testing"
)

func TestNewRPCRequestRejectsDisallowedMethod(t *testing.T) {
	_, err := newRPCRequest("user_add", []any{"eve"}, nil)
	if err == nil {
		t.Fatalf("expected user_add to be rejected by the allowlist")
	}
	if _, ok := errors.AsType[*ErrMethodNotAllowed](err); !ok {
		t.Fatalf("expected *ErrMethodNotAllowed, got %T: %v", err, err)
	}
}

func TestNewRPCRequestAllowsReadMethods(t *testing.T) {
	for method := range allowedMethods {
		if _, err := newRPCRequest(method, nil, nil); err != nil {
			t.Errorf("expected %s to be allowed: %v", method, err)
		}
	}
}

func TestNewRPCRequestShape(t *testing.T) {
	body, err := newRPCRequest("user_show", []any{"alice"}, map[string]any{"all": true})
	if err != nil {
		t.Fatalf("newRPCRequest: %v", err)
	}
	got := string(body)
	want := `{"method":"user_show","params":[["alice"],{"all":true}],"id":0}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
