package detection

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a 26-character Crockford base32 ULID: a 48-bit
// millisecond timestamp in the high bits followed by 80 bits of
// crypto-random entropy (spec §21: signal_id is a ULID). Encoded via
// plain base-32 big.Int division rather than hand-written bit-shift
// tables, trading a little speed (irrelevant — this runs once per new
// episode) for an implementation that is trivially checkable against
// go's own big.Int arithmetic instead of a manually-derived bit layout.
func NewULID() (string, error) {
	var entropy [10]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("ulid entropy: %w", err)
	}
	ms := time.Now().UnixMilli()
	raw := make([]byte, 16)
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	copy(raw[6:], entropy[:])

	n := new(big.Int).SetBytes(raw)
	base := big.NewInt(32)
	mod := new(big.Int)
	const length = 26
	out := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		n.DivMod(n, base, mod)
		out[i] = crockfordAlphabet[mod.Int64()]
	}
	return string(out), nil
}
