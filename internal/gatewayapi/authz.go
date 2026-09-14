package gatewayapi

import (
	"encoding/json"
	"io"
	"net/http"
)

// decodeStrictJSON rejects any request body field not present in T's
// struct tags. This is spec.md §22.4's "client 不能覆寫 Gateway scope"
// enforced as code, not merely as an unread field: a caller trying to
// smuggle username/gateway_id/scope/target_hostgroup into
// POST /v1/connect/authorize gets a 400, not a silently-ignored field.
func decodeStrictJSON[T any](r io.Reader, out *T) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}
