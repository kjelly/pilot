package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/kjelly/pilot/cmd/pilot/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code := 1
		var withCode cmd.ExitCoder
		if errors.As(err, &withCode) {
			code = withCode.ExitCode()
		}
		os.Exit(code)
	}
}
