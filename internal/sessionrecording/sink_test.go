package sessionrecording

import (
	"context"
	"testing"
)

func TestNullSinkNeverFails(t *testing.T) {
	var s NullSink
	if err := s.WriteBatch(context.Background(), []TerminalEvent{{}}); err != nil {
		t.Fatalf("NullSink.WriteBatch: %v", err)
	}
	if err := s.Finish(context.Background(), FinishInfo{}); err != nil {
		t.Fatalf("NullSink.Finish: %v", err)
	}
}
