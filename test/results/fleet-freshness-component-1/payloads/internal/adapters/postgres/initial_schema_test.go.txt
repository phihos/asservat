package postgres

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestInitialSchemaEmbeddedBundleAndClosedAnnotations(t *testing.T) {
	b, e := EmbeddedInitialSchema()
	if e != nil || b.Head != currentSchemaVersion || len(b.Digest) != 64 {
		t.Fatal("embedded pinned bundle", b, e)
	}
	t.Logf("actual embedded schema head=%d digest=%s", b.Head, b.Digest)
	valid := "-- +goose Up\nCREATE TABLE synthetic(id int);\n"
	source := func(s string) fstest.MapFS {
		return fstest.MapFS{"00001_synthetic.sql": &fstest.MapFile{Data: []byte(s)}}
	}
	if _, e := initialSchemaBundle(source(valid+"-- +goose Down\nSELECT 1;\n"), 1); e != nil {
		t.Fatal("existing optional Down source cannot be inspected", e)
	}
	a, e := initialSchemaBundle(source(valid), 1)
	if e != nil {
		t.Fatal(e)
	}
	changed, e := initialSchemaBundle(source(valid+"-- build change\n"), 1)
	if e != nil || a.Digest == changed.Digest {
		t.Fatal("bundle changed without identity change")
	}
	for _, bad := range []string{strings.Replace(valid, "Up", "Down", 1), valid + "-- +goose Down\n-- +goose Down\n", valid + "-- +goose NO TRANSACTION\n", valid + "--\t+goose NO TRANSACTION\n", valid + "-- +goose ENVSUB ON\n", valid + "-- +goose StatementBegin\n", valid + "-- +goose Up\n", strings.Repeat(" ", 513<<10)} {
		if _, e = initialSchemaBundle(source(bad), 1); e == nil {
			t.Fatal("unsafe Goose controls accepted")
		}
	}
	for _, bad := range []fstest.MapFS{{"00002_gap.sql": &fstest.MapFile{Data: []byte(valid)}}, {"00001_up.sql": &fstest.MapFile{Data: []byte(valid)}, "other.sql": &fstest.MapFile{Data: []byte(valid)}}} {
		if _, e = initialSchemaBundle(bad, 1); e == nil {
			t.Fatal("foreign/gapped bundle accepted")
		}
	}
}
func TestInitialSchemaHistoryRequiresOriginalOrderedUpPrefix(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	good := []initialSchemaVersion{{1, 0, true, now}, {2, 1, true, now.Add(time.Millisecond)}, {4, 2, true, now.Add(2 * time.Millisecond)}}
	if n, e := initialSchemaPrefix(good, 3); e != nil || n != 2 {
		t.Fatal("transactional sequence gap rejected", n, e)
	}
	cases := map[string]func([]initialSchemaVersion) []initialSchemaVersion{
		"missing-zero":    func(v []initialSchemaVersion) []initialSchemaVersion { return v[1:] },
		"out-of-order":    func(v []initialSchemaVersion) []initialSchemaVersion { v[1].Version = 2; v[2].Version = 1; return v },
		"down":            func(v []initialSchemaVersion) []initialSchemaVersion { v[1].Applied = false; return v },
		"foreign":         func(v []initialSchemaVersion) []initialSchemaVersion { v[2].Version = 99; return v },
		"duplicate":       func(v []initialSchemaVersion) []initialSchemaVersion { v[2].Version = 1; return v },
		"decreasing-id":   func(v []initialSchemaVersion) []initialSchemaVersion { v[2].ID = 1; return v },
		"decreasing-time": func(v []initialSchemaVersion) []initialSchemaVersion { v[2].At = now.Add(-time.Second); return v },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := initialSchemaPrefix(mutate(append([]initialSchemaVersion(nil), good...)), 3); e == nil {
				t.Fatal("noncanonical migration history accepted")
			}
		})
	}
}

type expiredInitialSchemaRoot struct{ reads int }

func (r *expiredInitialSchemaRoot) ReadInitialSchema(ctx context.Context) (contracts.InitialPreparationRoot, time.Time, error) {
	r.reads++
	return contracts.InitialPreparationRoot{}, time.Now().Add(-time.Millisecond), nil
}
func (r *expiredInitialSchemaRoot) ClaimInitialSchema(context.Context, contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	panic("claim after expired observation")
}
func (r *expiredInitialSchemaRoot) CompleteInitialSchema(context.Context, contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	panic("completion after expired observation")
}
func TestInitialSchemaRetainsExpiredCurrentRootBeforeSQL(t *testing.T) {
	r := &expiredInitialSchemaRoot{}
	s := &InitialSchema{root: r}
	if _, e := s.lease(context.Background()); e == nil || r.reads != 1 {
		t.Fatal("expired observation reached SQL", e)
	}
}
func TestInitialSchemaStoreCannotCreateOrDeleteViaGoose(t *testing.T) {
	s := initialSchemaStore{}
	if e := s.CreateVersionTable(context.Background(), nil); e != cfg.ErrUnavailable {
		t.Fatal("Goose could retry metadata creation", e)
	}
	if e := s.Delete(context.Background(), nil, 1); e != cfg.ErrUnavailable {
		t.Fatal("down mutation accepted", e)
	}
}
func TestInitialSchemaGrantUnionRemainsPurposeLimited(t *testing.T) {
	got := initialSchemaManagerGrants()
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g.key()] {
			t.Fatal("duplicate manager grant")
		}
		seen[g.key()] = true
		if g.privilege != "USAGE" && g.privilege != "SELECT" && g.privilege != "MAINTAIN" && g.privilege != "INSERT" && g.privilege != "UPDATE" {
			t.Fatal("expanded installer scope")
		}
		if g.privilege == "INSERT" && g.object != "fleet_initial_activation" && g.object != "fleet_trust" && g.object != "fleet_observation" {
			t.Fatal("unexpected insertion authority")
		}
		if g.privilege == "UPDATE" && g.column == "" {
			t.Fatal("unbounded update")
		}
	}
}

type shortInitialSchemaRoot struct {
	record contracts.InitialPreparationSchema
	until  time.Time
}

func (r *shortInitialSchemaRoot) ReadInitialSchema(context.Context) (contracts.InitialPreparationRoot, time.Time, error) {
	return contracts.InitialPreparationRoot{Schema: &r.record}, r.until, nil
}
func (r *shortInitialSchemaRoot) ClaimInitialSchema(context.Context, contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	panic("unused")
}
func (r *shortInitialSchemaRoot) CompleteInitialSchema(context.Context, contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	panic("unused")
}
func TestInitialSchemaShorterObservationCancelsAlreadyPassedSQLContext(t *testing.T) {
	r := &shortInitialSchemaRoot{record: contracts.InitialPreparationSchema{AttemptID: "original"}, until: time.Now().Add(time.Second)}
	s := &InitialSchema{root: r}
	l, e := s.lease(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { l.stop() }()
	alreadyPassedToGoose := l.ctx
	r.until = time.Now().Add(20 * time.Millisecond)
	if e = l.checkRoot(); e != nil {
		t.Fatal(e)
	}
	if got, _ := l.ctx.Deadline(); !got.Equal(r.until) {
		t.Fatal("shorter root deadline discarded")
	}
	select {
	case <-alreadyPassedToGoose.Done():
	case <-time.After(time.Second):
		t.Fatal("Goose retained broader original context")
	}
	if e = l.current(); e == nil {
		t.Fatal("expired narrower observation accepted")
	}
}
func TestInitialSchemaClaimAndCompletionBoundsCannotRenewLease(t *testing.T) {
	r := &shortInitialSchemaRoot{until: time.Now().Add(time.Second)}
	s := &InitialSchema{root: r}
	l, e := s.lease(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { l.stop() }()
	shorter := time.Now().Add(20 * time.Millisecond)
	if e = l.narrow(shorter); e != nil {
		t.Fatal(e)
	}
	if e = l.narrow(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	if got, _ := l.ctx.Deadline(); !got.Equal(shorter) {
		t.Fatal("later completion renewed original claim")
	}
	<-l.ctx.Done()
	if e = l.current(); e == nil {
		t.Fatal("SQL finalization retained stale claim")
	}
}
