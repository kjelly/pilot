package sessionstore

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMasterKeyFile_ReadsValidHexKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadMasterKeyFile(path)
	if err != nil {
		t.Fatalf("LoadMasterKeyFile: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("got %x, want %x", got, key)
	}
}

func TestLoadMasterKeyFile_RejectsWorldReadable(t *testing.T) {
	key := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadMasterKeyFile(path)
	if err == nil {
		t.Fatal("want error for world-readable master key file, got nil")
	}
	if !strings.Contains(err.Error(), "group/world accessible") {
		t.Fatalf("err = %v, want mode-related message", err)
	}
}

func TestLoadMasterKeyFile_RejectsInvalidHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("not-hex-at-all"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadMasterKeyFile(path)
	if err == nil {
		t.Fatal("want error for non-hex master key file, got nil")
	}
}

func TestLoadMasterKeyFile_RejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString([]byte("too-short"))), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadMasterKeyFile(path)
	if err == nil {
		t.Fatal("want error for wrong-length master key, got nil")
	}
}

func TestLoadMasterKeyFile_RejectsMissingFile(t *testing.T) {
	_, err := LoadMasterKeyFile(filepath.Join(t.TempDir(), "does-not-exist.key"))
	if err == nil {
		t.Fatal("want error for missing master key file, got nil")
	}
}
