package chunker

func contains(s []string, w string) bool {
	for _, v := range s {
		if v == w {
			return true
		}
	}
	return false
}
