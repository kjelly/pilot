package docs

// contains is a small string-slice membership helper shared across
// tests in this package. Kept in its own file (testhelpers_test.go)
// so individual test files don't need to redeclare it.
func contains(s []string, w string) bool {
	for _, v := range s {
		if v == w {
			return true
		}
	}
	return false
}
