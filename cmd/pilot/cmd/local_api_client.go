package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Policy resolution can require several FreeIPA RPC batches. Allow headroom
// beyond the old 10s cutoff while retaining the caller's cancellation/deadline.
const accessAPIRequestTimeout = 30 * time.Second

func localAPIRequestError(service string, req *http.Request, err error) error {
	var opErr *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s request %s %s canceled: %w", service, req.Method, req.URL.Path, err)
	case errors.As(err, &opErr) && opErr.Op == "dial":
		if os.IsTimeout(err) {
			return fmt.Errorf("%s socket connection timed out: %w", service, err)
		}
		return fmt.Errorf("%s socket connection failed: %w", service, err)
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return fmt.Errorf("%s request %s %s timed out waiting for a response: %w", service, req.Method, req.URL.Path, err)
	default:
		return fmt.Errorf("%s request %s %s failed: %w", service, req.Method, req.URL.Path, err)
	}
}
