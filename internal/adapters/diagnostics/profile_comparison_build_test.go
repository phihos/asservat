package diagnostics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	analysis "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/google/pprof/profile"
)

func TestPprofComparisonBuildWorkBoundUsesUnknown(t *testing.T) {
	p := comparisonFixture([]string{"work"}, []int64{1}, 10)
	// One shared string-table entry keeps this native profile below the 16 MiB
	// decompression limit. Rehashing that entry for every mapping amplifies work
	// beyond that limit, even with only nine permitted mappings.
	build := strings.Repeat("b", 2<<20)
	p.Mapping[0].BuildID = build
	for id := uint64(2); id <= 9; id++ {
		p.Mapping = append(p.Mapping, &profile.Mapping{ID: id, BuildID: build})
	}
	out, err := runComparison(t, p, p, comparisonSelection(t, analysis.ProfileComparisonRaw, 20))
	if err != nil || out.BuildStatus != "unknown" || len(out.Rows) != 1 || out.Rows[0].Delta != 0 {
		t.Fatal("optional build work must stay bounded without refusing valid aggregates", out, err)
	}
}

type comparisonBuildCancelContext struct {
	context.Context
	cancel           context.CancelFunc
	checks, cancelAt int
}

func (c *comparisonBuildCancelContext) Err() error {
	c.checks++
	if c.checks == c.cancelAt {
		c.cancel()
	}
	return c.Context.Err()
}

func TestPprofComparisonBuildCancellationWithinOneLongIdentifier(t *testing.T) {
	inner, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &comparisonBuildCancelContext{Context: inner, cancel: cancel, cancelAt: 7}
	p := &profile.Profile{Mapping: []*profile.Mapping{{BuildID: strings.Repeat("b", 2<<20)}}}
	// Cancellation occurs after hashing has started, before all of this single
	// identifier has been read. Per-mapping checks alone cannot pass this test.
	digest, known, err := comparisonBuild(ctx, p)
	if !errors.Is(err, context.Canceled) || known || digest != ([32]byte{}) || ctx.checks < ctx.cancelAt {
		t.Fatal("cancelled build computation retained a digest", known, err, ctx.checks)
	}
}

func TestPprofComparisonBuildWorkIncludesDigestFraming(t *testing.T) {
	// This helper-level boundary does not assert that such a large string plus
	// a complete native profile fits the separate decompression limit.
	p := &profile.Profile{Mapping: []*profile.Mapping{{BuildID: strings.Repeat("b", artifact.MaxPprofDecompressedBytes-sha256.Size)}}}
	if _, known, err := comparisonBuild(t.Context(), p); err != nil || !known {
		t.Fatal("exact hash-work boundary refused", known, err)
	}
	p.Mapping[0].BuildID += "b"
	if digest, known, err := comparisonBuild(t.Context(), p); err != nil || known || digest != ([32]byte{}) {
		t.Fatal("digest framing omitted from work bound", known, err)
	}
}

func TestPprofComparisonBuildKnownSetRemainsOrderIndependent(t *testing.T) {
	p := &profile.Profile{Mapping: []*profile.Mapping{{BuildID: "build-a"}, {BuildID: "build-b"}, {BuildID: "build-a"}}}
	digest, known, err := comparisonBuild(t.Context(), p)
	if err != nil || !known {
		t.Fatal(known, err)
	}
	a, b := sha256.Sum256([]byte("build-a")), sha256.Sum256([]byte("build-b"))
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	expected := sha256.Sum256(append(a[:], b[:]...))
	if digest != expected {
		t.Fatal("known build digest encoding changed")
	}
	p.Mapping[0], p.Mapping[1] = p.Mapping[1], p.Mapping[0]
	p.Mapping = p.Mapping[:2]
	if again, known, err := comparisonBuild(t.Context(), p); err != nil || !known || again != digest {
		t.Fatal("mapping order/multiplicity changed build set", known, err)
	}
	for _, p := range []*profile.Profile{{}, {Mapping: []*profile.Mapping{{BuildID: ""}}}} {
		if digest, known, err := comparisonBuild(t.Context(), p); err != nil || known || digest != ([32]byte{}) {
			t.Fatal("unknown build facts invented a digest", known, err)
		}
	}
}
