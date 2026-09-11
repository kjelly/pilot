package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// AnnotationUserClassPrefix namespaces every FreeIPA `userClass` value
	// Pilot owns (spec.md §3.4) — only values carrying this prefix are ever
	// added, modified, or deleted by the annotation projection; every other
	// `userClass` value on a host is foreign and must be preserved verbatim.
	AnnotationUserClassPrefix = "pilot.annotation."
	// MaxAnnotationsPerHost is the V1 abuse/accidental-data-dump ceiling
	// (spec.md §4.7) — not a FreeIPA `userClass` cardinality limit.
	MaxAnnotationsPerHost = 32
	// MaxUserClassValueBytes is FreeIPA's own per-value limit on a
	// multi-valued `userClass` attribute (spec.md §4.6); the serialized
	// "pilot.annotation.<key>=<value>" string must fit under it, or the
	// projection would fail at `ipa host-mod` time instead of at lint time.
	MaxUserClassValueBytes = 256
)

// annotationKeyPattern is the Key contract from spec.md §4.4: lowercase,
// ASCII, starting with a letter. All-lowercase avoids `Project`/`project`
// aliasing against FreeIPA `userClass` case-insensitive equality (spec.md
// §2.4), and the restricted charset keeps parsing/CLI/Portal handling
// simple.
var annotationKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

// ValidateAnnotationKey enforces spec.md §4.4's key contract plus the §4.8
// secret prohibition. Key validity does not depend on the value, so it is
// checked independently of ValidateAnnotationValue.
func ValidateAnnotationKey(key string) error {
	if !annotationKeyPattern.MatchString(key) {
		return fmt.Errorf("annotation key %q is invalid: must match ^[a-z][a-z0-9_.-]{0,62}$", key)
	}
	if LooksSecretLike(key) {
		return fmt.Errorf("annotation %q looks secret-bearing; annotations are projected to FreeIPA and must contain non-secret descriptive metadata only", key)
	}
	return nil
}

// ValidateAnnotationValue enforces spec.md §4.5's value contract. Emptiness
// and whitespace/control-character checks are independent of the key.
func ValidateAnnotationValue(value string) error {
	if value == "" {
		return fmt.Errorf("annotation value must not be empty")
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("annotation value must not have leading/trailing whitespace")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("annotation value must not contain a carriage return, newline, or NUL byte")
	}
	return nil
}

// SerializeAnnotation returns the FreeIPA `userClass` value Pilot would
// write for key/value (spec.md §7.1: no base64/JSON/URL encoding, so the
// value stays human-readable in the FreeIPA UI/CLI), failing if it exceeds
// FreeIPA's own per-value length limit (spec.md §4.6) — this must be caught
// here, at lint/validate time, not first discovered at `ipa host-mod` time.
func SerializeAnnotation(key, value string) (string, error) {
	serialized := AnnotationUserClassPrefix + key + "=" + value
	if len(serialized) > MaxUserClassValueBytes {
		return "", fmt.Errorf("annotation %q serialized value is %d bytes, exceeds FreeIPA userClass limit of %d bytes", key, len(serialized), MaxUserClassValueBytes)
	}
	return serialized, nil
}

// ValidateAnnotations validates every key/value pair in annotations plus
// the per-host count ceiling (spec.md §4.7), returning one error per
// problem found — never bailing out on the first bad entry, so `pilot
// inventory lint` / `pilot edit` can surface every issue in one pass.
func ValidateAnnotations(annotations map[string]string) []error {
	var errs []error
	if len(annotations) > MaxAnnotationsPerHost {
		errs = append(errs, fmt.Errorf("host has %d annotations, exceeds the max of %d per host", len(annotations), MaxAnnotationsPerHost))
	}
	for _, key := range sortedKeys(annotations) {
		value := annotations[key]
		if err := ValidateAnnotationKey(key); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := ValidateAnnotationValue(value); err != nil {
			errs = append(errs, fmt.Errorf("annotation %q: %w", key, err))
			continue
		}
		if _, err := SerializeAnnotation(key, value); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
