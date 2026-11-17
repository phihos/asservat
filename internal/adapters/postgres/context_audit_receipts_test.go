package postgres

import (
	"testing"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"github.com/jackc/pgx/v5/pgtype"
)

func publishedCatalogFixture(t *testing.T) custodydb.ReadPublishedContextRow {
	t.Helper()
	f := progressFactsFixture(t, "published")
	c := f.ContextCapture
	cat := custodydb.ContextCatalog{ArtifactID: f.CatalogArtifactID, CaptureID: c.ID, RootID: c.RootID, PublishedAt: f.PublishedAt, CopiesDigest: f.CopiesDigest}
	return custodydb.ReadPublishedContextRow{ContextCapture: c, ContextCatalog: cat, EffectiveExpiresAt: f.EffectiveExpiresAt, EffectiveDeleteBy: f.EffectiveDeleteBy}
}
func TestCurrentCatalogRequiresOriginalRows(t *testing.T) {
	row := publishedCatalogFixture(t)
	if _, e := currentPublishedContext(row); e != nil {
		t.Fatal("original committed context", e)
	}
	for name, mutate := range map[string]func(*custodydb.ReadPublishedContextRow){
		"capture": func(r *custodydb.ReadPublishedContextRow) { r.ContextCatalog.CaptureID = r.ContextCapture.RootID },
		"copies-size": func(r *custodydb.ReadPublishedContextRow) {
			r.ContextCatalog.CopiesDigest = r.ContextCatalog.CopiesDigest[:31]
		},
		"late-publication": func(r *custodydb.ReadPublishedContextRow) { r.ContextCatalog.PublishedAt = r.ContextCapture.Deadline },
	} {
		t.Run(name, func(t *testing.T) {
			bad := row
			mutate(&bad)
			if _, e := currentPublishedContext(bad); e == nil {
				t.Fatal("changed retained catalog authorized current access")
			}
		})
	}
}
func TestCurrentCatalogNativeLengthIsBounded(t *testing.T) {
	row := publishedCatalogFixture(t)
	e, err := currentPublishedContext(row)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{0, 353, e.Registration.NativeLimit} {
		row.ContextCatalog.NativeBytes = pgtype.Int8{Int64: size, Valid: true}
		if _, err := currentPublishedContext(row); err != nil {
			t.Fatal("stored length refused", size, err)
		}
	}
	for _, size := range []int64{-1, e.Registration.NativeLimit + 1} {
		row.ContextCatalog.NativeBytes = pgtype.Int8{Int64: size, Valid: true}
		if _, err := currentPublishedContext(row); err == nil {
			t.Fatal("invalid stored length accepted", size)
		}
	}
}
