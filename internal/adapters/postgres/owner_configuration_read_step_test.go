package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Blocking before connection establishment reproduces pool acquisition expiry
// without a database or a successful connection. The public reader must report
// this separately from a SQL predicate which rejects an expired observation.
func TestOwnerConfigurationReadStepBeginDeadline(t *testing.T) {
	config, err := pgxpool.ParseConfig("host=127.0.0.1 port=1 user=unused password=unused dbname=unused sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	config.BeforeConnect = func(context.Context, *pgx.ConnConfig) error {
		close(entered)
		<-release
		defer close(finished)
		return errors.New("private-connection-detail")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() {
		close(release)
		select {
		case <-entered:
			<-finished
		default:
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := (&OwnerConfigurations{ledger: &Ledger{pool: pool}}).ReadOwnerConfiguration(ctx)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("pool did not enter the blocked connection hook")
	}
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("reader did not preserve its caller deadline")
	}
	var step interface{ FixedStep() string }
	if !errors.Is(err, privacy.ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != "transaction/begin-deadline" {
		t.Fatalf("pool deadline lost its sanitized stage: %v", err)
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatal("fixture did not reach the original caller deadline")
	}
}

func TestOwnerConfigurationReadStepKeepsClosedTransactionCauses(t *testing.T) {
	for _, tc := range []struct{ cause, want string }{
		{"begin-deadline", "begin-deadline"},
		{"begin-credential", "begin-credential"},
		{"begin-dial", "begin-dial"},
		{"begin-tls", "begin-tls"},
		{"begin-server", "begin-server"},
		{"begin-connect", "begin-connect"},
		{"begin-acquire", "begin-acquire"},
		{"deadline", "deadline"},
		{"client", "client"},
		{"retries", "retries"},
		{"sql-55P03", "lock-timeout"},
		{"sql-57014", "query-cancelled"},
		{"sql-42501", "permission"},
		{"sql-53300", "connection-limit"},
		{"sql-40001", "serialization"},
		{"sql-40P01", "deadlock"},
		{"sql-other", "unspecified"},
		{"begin-private-token", "unspecified"},
	} {
		t.Run(tc.cause, func(t *testing.T) {
			cause := unavailableCause(tc.cause)
			err := (ownerConfigurationReadDiagnostic{}).failure(cause)
			var step interface{ FixedStep() string }
			if !errors.Is(err, privacy.ErrUnavailable) || errors.Unwrap(err) != cause || !errors.As(err, &step) || step.FixedStep() != "transaction/"+tc.want {
				t.Fatalf("transaction diagnostic changed identity or escaped its vocabulary: %v", err)
			}
		})
	}
	// A query/predicate already names its own actual failure; a generic outer
	// ledger result cannot replace that more precise statement classification.
	err := (ownerConfigurationReadDiagnostic{ownerReadHead, ownerReadLockTimeout}).failure(unavailableCause("deadline"))
	var step interface{ FixedStep() string }
	if !errors.As(err, &step) || step.FixedStep() != "share-owner/lock-timeout" {
		t.Fatal("transaction result replaced the actual failed statement")
	}
}
