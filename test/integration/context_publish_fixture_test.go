package integration

import (
	"context"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publishedContext is what one-step publication leaves behind for fixtures.
type publishedContext struct {
	RootID, CaptureID string
	Expectation       artifact.ContextExpectation
	Copies            artifact.Copies
	Catalog           artifact.CatalogFacts
	PublishedAt       time.Time
}

// Source is the stored artifact as a read receives it from the catalog.
func (p publishedContext) Source() evidence.NativeContextSource {
	return evidence.NativeContextSource{Expectation: p.Expectation, Copies: p.Copies, Catalog: p.Catalog}
}

// catalogFactsFixture reads the native size and profile window that the
// stored outcome wrote into the catalog row.
func catalogFactsFixture(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, captureID string) (artifact.CatalogFacts, error) {
	var f artifact.CatalogFacts
	var started, completed *time.Time
	if err := q.QueryRow(ctx, "SELECT native_bytes,acquisition_started_at,acquisition_completed_at FROM context_catalog WHERE capture_id=$1", captureID).Scan(&f.NativeBytes, &started, &completed); err != nil {
		return f, err
	}
	if started != nil && completed != nil {
		f.Acquisition = &artifact.AcquisitionWindow{StartedAt: started.UTC(), CompletedAt: completed.UTC()}
	}
	return f, nil
}

// podStatusSource is a stored pod-status artifact with its catalog native size.
func podStatusSource(e artifact.ContextExpectation, copies artifact.Copies, native []byte) evidence.NativeContextSource {
	return evidence.NativeContextSource{Expectation: e, Copies: copies, Catalog: artifact.CatalogFacts{NativeBytes: int64(len(native))}}
}

// storedFacts are the native size and profile window the producer reports
// with its writer completion, as publication stores them in the catalog row.
func storedFacts(p *objectstore.PreparedArtifact) artifact.CatalogFacts {
	var c artifact.ContextWriterCompletion
	p.AddFacts(&c)
	return artifact.CatalogFacts{NativeBytes: c.NativeBytes, Acquisition: c.Acquisition}
}

// publishStoredFixture stands in for the stored-outcome transaction
// (REQ-EVD-001) when a fixture stores an artifact without an API execution:
// in one transaction it records the copy receipts, marks the attempt stored and
// inserts the catalog row with the producer's native facts. Replays return the
// existing row. The administrator pool replaces the API execution role here.
func publishStoredFixture(ctx context.Context, admin *pgxpool.Pool, e artifact.ContextExpectation, copies artifact.Copies, nativeBytes int64, window *artifact.AcquisitionWindow) (publishedContext, error) {
	out := publishedContext{CaptureID: e.CaptureUID, Expectation: e, Copies: copies, Catalog: artifact.CatalogFacts{NativeBytes: nativeBytes, Acquisition: window.Clone()}}
	if err := copies.Validate(e.Registration); err != nil {
		return out, err
	}
	version := evidence.ContextCopiesDigest(copies)
	var started, completed *time.Time
	if window != nil {
		started, completed = &window.StartedAt, &window.CompletedAt
	}
	attempt := e.Registration.Location.AttemptID
	err := pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM custody_allocation WHERE id=$1 FOR UPDATE", e.Registration.AllocationID); err != nil {
			return err
		}
		var state string
		if err := tx.QueryRow(ctx, "SELECT state FROM custody_attempt WHERE id=$1 FOR UPDATE", attempt).Scan(&state); err != nil {
			return err
		}
		if state == artifact.Reserved {
			for i, c := range copies {
				var versionID *string
				if c.VersionID != "" {
					versionID = &c.VersionID
				}
				if _, err := tx.Exec(ctx, "UPDATE custody_copy SET ciphertext_bytes=$3,ciphertext_sha256=$4,etag=$5,version_id=$6 WHERE attempt_id=$1 AND role=$2", attempt, i, c.Bytes, c.SHA256[:], c.ETag, versionID); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, "UPDATE custody_attempt SET state='stored_unpublished',copies_digest=$2 WHERE id=$1", attempt, version[:]); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO custody_event(attempt_id,phase) VALUES ($1,'stored') ON CONFLICT DO NOTHING", attempt); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO context_catalog(artifact_id,capture_id,root_id,copies_digest,native_bytes,acquisition_started_at,acquisition_completed_at)
SELECT $1,c.id,c.root_id,a.copies_digest,$3,$4,$5 FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id WHERE c.id=$2
ON CONFLICT (capture_id) DO NOTHING`, e.Registration.Location.ArtifactID, e.CaptureUID, nativeBytes, started, completed); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT root_id::text,published_at FROM context_catalog WHERE capture_id=$1 AND copies_digest=$2", e.CaptureUID, version[:]).Scan(&out.RootID, &out.PublishedAt)
	})
	return out, err
}

// readStoredNative reads a stored artifact the way every read does: commit,
// manifest and index against e, then every frame by its AEAD tag and the
// whole-file hash. It replaces the removed publication-time verification.
func readStoredNative(ctx context.Context, v *objectstore.ContextVerifier, s evidence.NativeContextSource) ([]byte, error) {
	source, err := v.OpenNative(ctx, s, time.Now().Add(30*time.Second))
	if err != nil {
		return nil, err
	}
	defer source.Close()
	size := source.Metadata().Size
	out := make([]byte, 0, size)
	for offset := int64(0); offset < size; {
		chunk, _, err := source.ReadNext(ctx, offset, min(int64(1<<20), size-offset))
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		out = append(out, chunk...)
		offset += int64(len(chunk))
	}
	return out, nil
}
