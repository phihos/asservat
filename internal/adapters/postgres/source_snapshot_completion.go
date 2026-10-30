package postgres

import (
	"bytes"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

// The original admitted expectation remains the independent source of facts.
// Stored coverage can only refine coverage, never choose scope, clocks or keys.
func storedSnapshotProjection(e artifact.ContextExpectation, raw, coverageDigest, finalDigest []byte) (artifact.ContextExpectation, error) {
	if len(raw) == 0 {
		if len(coverageDigest) != 0 || len(finalDigest) != 0 {
			return artifact.ContextExpectation{}, value.ErrChanged
		}
		return e, nil
	}
	if e.Snapshot == nil || !evidence.ValidSourceSnapshotManifest(e) || len(raw) > 8192 || len(coverageDigest) != 32 || len(finalDigest) != 32 {
		return artifact.ContextExpectation{}, value.ErrChanged
	}
	var coverage artifact.SourceSnapshotCoverage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&coverage) != nil {
		return artifact.ContextExpectation{}, value.ErrChanged
	}
	canonical, err := json.Marshal(coverage)
	if err != nil || !bytes.Equal(canonical, raw) || !bytes.Equal(digest(coverage), coverageDigest) {
		return artifact.ContextExpectation{}, value.ErrChanged
	}
	projected, err := artifact.ProjectSourceSnapshotCoverage(e, evidence.ContextExpectationDigest(e), coverage)
	if err != nil || !bytes.Equal(digest(projected), finalDigest) {
		return artifact.ContextExpectation{}, value.ErrChanged
	}
	return projected, nil
}

func checkSnapshotCompletion(row custodydb.ContextCapture, acceptedDigest artifact.Digest, coverage artifact.SourceSnapshotCoverage) (artifact.ContextExpectation, error) {
	accepted, err := admittedRecord(row)
	if err != nil || evidence.ContextExpectationDigest(accepted.Expectation) != acceptedDigest {
		return artifact.ContextExpectation{}, value.ErrChanged
	}
	raw, err := json.Marshal(coverage)
	if err != nil || !bytes.Equal(raw, row.SnapshotCoverage) {
		return artifact.ContextExpectation{}, value.ErrConflict
	}
	return storedSnapshotProjection(accepted.Expectation, row.SnapshotCoverage, row.SnapshotCoverageDigest, row.SnapshotExpectationDigest)
}
