package objectstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// TestReadRefusesCatalogMismatch reproduces REQ-EVD-001: a read compares the
// catalog row's native size and Go-profile acquisition window with the
// authenticated manifest and fails with Integrity on any difference.
func TestReadRefusesCatalogMismatch(t *testing.T) {
	dir := t.TempDir()
	f := prepareProfileEncryptedFixture(t, dir, bytes.NewReader(comparisonEncryptedNative(t, 7)), false)
	for _, mode := range []string{"match", "size", "start", "end", "missing-window"} {
		t.Run(mode, func(t *testing.T) {
			g := f
			g.Source.Catalog.Acquisition = f.Source.Catalog.Acquisition.Clone()
			switch mode {
			case "size":
				g.Source.Catalog.NativeBytes--
			case "start":
				g.Source.Catalog.Acquisition.StartedAt = g.Source.Catalog.Acquisition.StartedAt.Add(-time.Microsecond)
			case "end":
				g.Source.Catalog.Acquisition.CompletedAt = g.Source.Catalog.Acquisition.CompletedAt.Add(time.Microsecond)
			case "missing-window":
				g.Source.Catalog.Acquisition = nil
			}
			verifier, _, _, _ := profileEncryptedVerifier(t, dir, g, false)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			opened, err := verifier.OpenNative(ctx, g.Source, until)
			if mode == "match" {
				if err != nil {
					t.Fatal("matching catalog row refused", err)
				}
				opened.Close()
				return
			}
			if !errors.Is(err, artifact.ErrIntegrity) {
				t.Fatal("catalog mismatch not refused as integrity", err)
			}
		})
	}
}
