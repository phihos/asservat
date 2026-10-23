package analysis

import (
	"context"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/analysis"
)

type fixedCause struct{}

func (fixedCause) Error() string     { return "private dependency text" }
func (fixedCause) FixedStep() string { return "environment/policy" }

// A refused excerpt or poll is reported once with its closed stage path; the
// returned class is unchanged and no dependency text enters the stage name.
func TestQueryRefusalNamesTheRefusingStage(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*projectionFixture, *projectionInvocationFake)
		want   string
	}{
		{"read-scope", func(f *projectionFixture, _ *projectionInvocationFake) { f.i.Scopes = []string{"evidence:download"} }, "read-scope"},
		{"intent", func(_ *projectionFixture, i *projectionInvocationFake) { i.intentErr = value.ErrUnavailable }, "intent"},
		{"authority", func(f *projectionFixture, _ *projectionInvocationFake) { f.authorityErr = fixedCause{} }, "authority/environment/policy"},
		{"admit", func(f *projectionFixture, _ *projectionInvocationFake) { f.queryErr = errors.New("commit reply lost") }, "admit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newProjectionFixture(t)
			var reports []string
			f.s.Results.Refused = func(_ context.Context, op string, err error) {
				var fixed interface{ FixedStep() string }
				if !errors.As(err, &fixed) {
					t.Fatal("refusal without a stage")
				}
				reports = append(reports, op+"/"+fixed.FixedStep())
			}
			i := f.invocation("get_file_excerpt")
			c.change(f, i)
			_, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection)
			if !errors.Is(err, value.ErrUnavailable) && !errors.Is(err, value.ErrExpired) {
				t.Fatalf("returned class changed: %v", err)
			}
			if len(reports) != 1 || reports[0] != "excerpt/"+c.want {
				t.Fatalf("%q, want excerpt/%s", reports, c.want)
			}
		})
	}
	f := newProjectionFixture(t)
	reported := 0
	f.s.Results.Refused = func(context.Context, string, error) { reported++ }
	if _, i := f.begin(t); i == nil || reported != 0 {
		t.Fatal("successful excerpt reported as refused")
	}
}
