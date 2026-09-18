package directoryapi

import (
	"encoding/json"
	"io"
	"net/http"
)

// decodeStrictJSON rejects any request body field not present in T's
// struct tags — same discipline as internal/gatewayapi's helper of the
// same name (a caller trying to smuggle user/scope/gateway/session_id
// into POST /v1/connect/resolve gets a 400, not a silently-ignored
// field).
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
