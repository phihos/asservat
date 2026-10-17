package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

type bootstrapSchemaSource struct {
	first, current contracts.InitialPreparationRoot
	until          time.Time
	handover       bool
	reads, opens   int
	read           func(context.Context) error
}

func (s *bootstrapSchemaSource) ReadHandover(context.Context) (contracts.InitialPreparationRoot, bool, error) {
	return s.first, s.handover, nil
}
func (s *bootstrapSchemaSource) Open(context.Context) (contracts.InitialPreparationRoot, error) {
	s.opens++
	return s.current, nil
}
func (s *bootstrapSchemaSource) ReadInitialSchema(ctx context.Context) (contracts.InitialPreparationRoot, time.Time, error) {
	s.reads++
	if s.read != nil {
		if err := s.read(ctx); err != nil {
			return contracts.InitialPreparationRoot{}, time.Time{}, err
		}
	}
	return s.current, s.until, nil
}
func bootstrapSchemaFixture() (contracts.InitialPreparer, postgres.InitialSchemaBundle, *bootstrapSchemaSource) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := contracts.InitialSQLHistoryManager{Name: "original-manager", OID: 20001}
	c := contracts.InitialPreparer{Plan: contracts.InitialPreparationPlan{SchemaInitialization: contracts.InitialSchemaProtocol, InstallationID: "original-installation", RequestID: "original-request", HistoryManager: &m}}
	b := postgres.InitialSchemaBundle{Digest: strings.Repeat("a", 64), Head: 49}
	w := contracts.InitialPreparationRoot{RootUID: "original-root", InstallationID: c.Plan.InstallationID, RequestID: c.Plan.RequestID, PlanDigest: strings.Repeat("b", 64), Phase: "declaring", Creates: []contracts.InitialPreparationCreate{}, Schema: &contracts.InitialPreparationSchema{BundleDigest: b.Digest, Head: b.Head, Manager: m, DatabaseOID: 16384, PostmasterAt: now.Add(-time.Hour), ClaimedAt: now.Add(-time.Minute), CompletedAt: &now}}
	return c, b, &bootstrapSchemaSource{first: w, current: w, until: now.Add(5 * time.Second)}
}
func TestInitialBootstrapSchemaCompletedSkipsSetupForInterruptedAndRetiredRuns(t *testing.T) {
	for _, handover := range []bool{false, true} {
		c, b, s := bootstrapSchemaFixture()
		s.handover = handover
		needed, err := initialBootstrapSchemaNeeded(context.Background(), s, c, b, time.Now)
		if err != nil || needed || s.opens != 0 || s.reads != 1 {
			t.Fatal("completed original schema reopened setup stage", needed, err)
		}
	}
}
func TestInitialBootstrapSchemaNeedsOriginalPrefixButNeverRecreatesKnownRoot(t *testing.T) {
	c, b, s := bootstrapSchemaFixture()
	s.first.Schema = nil
	s.current.Schema = nil
	needed, err := initialBootstrapSchemaNeeded(context.Background(), s, c, b, time.Now)
	if err != nil || !needed || s.opens != 0 {
		t.Fatal("unstarted original schema denied", err)
	}
	s.first = contracts.InitialPreparationRoot{}
	c.RootUID = "known-original"
	if _, err = initialBootstrapSchemaNeeded(context.Background(), s, c, b, time.Now); err == nil || s.opens != 0 {
		t.Fatal("known missing root recreated")
	}
}
func TestInitialBootstrapSchemaRejectsContradictoryCompletion(t *testing.T) {
	for _, mode := range []string{"root", "plan", "installation", "request", "head", "bundle", "manager", "disappeared", "rewritten-incarnation", "completion-disappeared"} {
		t.Run(mode, func(t *testing.T) {
			c, b, s := bootstrapSchemaFixture()
			copy := *s.current.Schema
			s.current.Schema = &copy
			switch mode {
			case "root":
				s.current.RootUID = "replacement"
			case "plan":
				s.current.PlanDigest = strings.Repeat("c", 64)
			case "installation":
				s.current.InstallationID = "replacement"
			case "request":
				s.current.RequestID = "replacement"
			case "head":
				s.current.Schema.Head++
			case "bundle":
				s.current.Schema.BundleDigest = strings.Repeat("c", 64)
			case "manager":
				s.current.Schema.Manager.OID++
			case "disappeared":
				s.current.Schema = nil
			case "rewritten-incarnation":
				s.current.Schema.PostmasterAt = s.current.Schema.PostmasterAt.Add(time.Second)
			case "completion-disappeared":
				s.current.Schema.CompletedAt = nil
			}
			if needed, err := initialBootstrapSchemaNeeded(context.Background(), s, c, b, time.Now); err == nil || needed || s.opens != 0 {
				t.Fatal("contradictory record selected setup or skipped successfully", needed, err)
			}
		})
	}
}
func TestInitialBootstrapSchemaRetainsOriginalObservationAndParentDeadline(t *testing.T) {
	c, b, s := bootstrapSchemaFixture()
	now := time.Now()
	s.until = now.Add(time.Second)
	if _, err := initialBootstrapSchemaNeeded(context.Background(), s, c, b, func() time.Time { return now.Add(2 * time.Second) }); err == nil {
		t.Fatal("expired original observation accepted")
	}
	ctx, end := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer end()
	s.read = func(read context.Context) error {
		original, _ := ctx.Deadline()
		actual, _ := read.Deadline()
		if actual.After(original) {
			return errors.New("parent deadline extended")
		}
		<-read.Done()
		return read.Err()
	}
	if _, err := initialBootstrapSchemaNeeded(ctx, s, c, b, time.Now); err == nil {
		t.Fatal("completed schema ignored original cancellation")
	}
}
