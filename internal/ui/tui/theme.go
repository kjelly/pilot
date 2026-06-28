// Package tui: theme detection.
package tui

import (
	"os"
	"strings"
)

// DetectTheme inspects the environment to decide if the terminal is using
// a dark background. It uses several heuristics in order of decreasing
// reliability:
//
//  1. $COLORFGBG — many terminals set this to "fg;bg" with the background
//     in the second position. Color numbers above 7 typically mean a
//     light background (or a 256-color palette). We treat the second
//     component modulo 8 as the conventional "color slot".
//  2. $TERM — coarse hint: some terminals advertise themselves as
//     "*-light" or have "light" in the name.
//  3. Default to dark — server terminals (the common case for
//     pilot) are dark.
//
// The returned value is best-effort and used purely for choosing a palette;
// it is never sent to the model and never affects logic.
func DetectTheme() bool {
	// 1. COLORFGBG — most reliable when set.
	if cfb := os.Getenv("COLORFGBG"); cfb != "" {
		parts := strings.Split(cfb, ";")
		if len(parts) >= 2 {
			bg := strings.TrimSpace(parts[1])
			switch bg {
			case "15", "7": // classic light backgrounds
				return false
			case "0", "8": // classic dark backgrounds
				return true
			}
			// Generic: 0-7 dark, 8-15 light
			if isAllDigits(bg) && len(bg) <= 2 {
				var n int
				for _, r := range bg {
					n = n*10 + int(r-'0')
				}
				return n < 8
			}
		}
	}

	// 2. TERM-based heuristics
	term := strings.ToLower(os.Getenv("TERM"))
	if strings.Contains(term, "light") {
		return false
	}
	if strings.Contains(term, "dark") {
		return true
	}

	// 3. Default — assume dark
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
