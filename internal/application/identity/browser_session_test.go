package identity

import (
	"context"
	"errors"
	"testing"
)

type cleanupFunc func(context.Context) error

func (f cleanupFunc) Cleanup(ctx context.Context) error { return f(ctx) }
func TestSessionCleanupReportsFailureAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := RunSessionCleanup(ctx, cleanupFunc(func(context.Context) error { calls++; return errors.New("synthetic cleanup failure") }), func(err error) {
		if err == nil {
			t.Error("cleanup failure hidden")
		}
		cancel()
	})
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatal("cleanup lifecycle did not stop")
	}
}

func TestLocalReturnPath(t *testing.T) {
	for _, s := range []string{"/", "/cases/abc", "/investigations?tab=packets", "/investigations?q=pod%20name"} {
		if !LocalReturnPath(s) {
			t.Errorf("valid return %q rejected", s)
		}
	}
	for _, s := range []string{"", "https://evil.invalid", "//evil.invalid", "/\\evil.invalid", "/%2f%2fevil.invalid", "/%5cevil.invalid", "/%252fevil.invalid", "/ok%0d%0aLocation:evil", "/ok#fragment", "\n/path"} {
		if LocalReturnPath(s) {
			t.Errorf("unsafe return %q accepted", s)
		}
	}
}
