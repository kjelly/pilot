package spec

import "strings"

func joinFindings(fs []Finding) string {
	var sb strings.Builder
	for _, f := range fs {
		sb.WriteString(f.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}
