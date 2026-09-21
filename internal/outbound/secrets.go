package outbound

import (
	"os"
	"strings"
)

// ResolveAuthSecret loads the configured auth secret at delivery time. A
// secret_file may contain trailing newlines and, for bearer auth, an optional
// "Bearer " prefix. The returned value is never persisted by the outbound
// package.
func ResolveAuthSecret(auth AuthConfig, envLookup SecretLookup) (string, bool) {
	if auth.SecretFile != "" {
		data, err := os.ReadFile(auth.SecretFile)
		if err != nil {
			return "", false
		}
		return normalizeFileSecret(auth.Type, data)
	}
	if envLookup == nil {
		return "", false
	}
	return envLookup(auth.SecretEnv)
}

// AuthSecretSource returns a safe description of the configured secret
// source. It deliberately never includes a secret value.
func AuthSecretSource(auth AuthConfig) string {
	if auth.SecretFile != "" {
		return "secret file " + auth.SecretFile
	}
	return "environment variable " + auth.SecretEnv
}

func normalizeFileSecret(authType AuthType, data []byte) (string, bool) {
	secret := strings.TrimRight(string(data), "\r\n")
	if authType == AuthBearer {
		secret = strings.TrimPrefix(secret, "Bearer ")
	}
	return secret, secret != ""
}
