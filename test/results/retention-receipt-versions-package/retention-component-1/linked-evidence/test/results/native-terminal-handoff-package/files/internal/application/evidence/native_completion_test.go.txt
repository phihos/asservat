package evidence

import (
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"errors"
	"testing"
)

type completionOwners struct {
	NativeOperations
	completes, cleans int
	err               error
}

func (s *completionOwners) CompleteNativeOperation(context.Context, value.NativeLease) error {
	s.completes++
	return s.err
}
func (s *completionOwners) ReleaseNativeOperation(context.Context, value.NativeOperation) error {
	s.cleans++
	return s.err
}
func TestNativeCompletionNeverReplaysUnknownCloseOrUsesCleanupAsProof(t *testing.T) {
	for _, mode := range []string{"positive", "unknown", "cleanup-first", "wrong-generation"} {
		t.Run(mode, func(t *testing.T) {
			l := nativeLeaseFixture()
			s := &completionOwners{}
			if mode == "unknown" {
				s.err = errors.New("synthetic unknown commit")
			}
			r := &nativeOperationRelease{owners: s, operation: l.Operation}
			if mode == "cleanup-first" {
				if e := r.cleanup(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "wrong-generation" {
				l.Operation.Reference.Fence++
			}
			first := r.complete(context.Background(), l)
			second := r.complete(context.Background(), l)
			if mode == "positive" && (first != nil || second != nil) {
				t.Fatal(first, second)
			}
			if mode != "positive" && (first == nil || second == nil) {
				t.Fatal("unproven close accepted")
			}
			_ = r.cleanup(context.Background())
			if s.completes+s.cleans != 1 {
				t.Fatal("close retried", s.completes, s.cleans)
			}
			if mode == "cleanup-first" && s.completes != 0 {
				t.Fatal("cleanup converted into current completion")
			}
		})
	}
}
