package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type processingRefusalFixture struct {
	t        *testing.T
	ctx      context.Context
	cancel   context.CancelFunc
	cancelAt string
	reads    []string
	deadline time.Time
	identity identity.Identity
	policy   value.DownloadPolicy
}

func (f *processingRefusalFixture) read(ctx context.Context, stage string) {
	f.reads = append(f.reads, stage)
	got, bounded := ctx.Deadline()
	want, originalBound := f.ctx.Deadline()
	if !bounded || originalBound && !got.Equal(want) || !originalBound && got.After(time.Now().Add(5*time.Second)) {
		f.t.Error("diagnostic dependency extended the original deadline or five-second ceiling")
	}
	if !f.deadline.IsZero() && !got.Equal(f.deadline) {
		f.t.Error("diagnostic deadline renewed between dependency reads")
	}
	f.deadline = got
	if stage == f.cancelAt {
		f.cancel()
		if ctx.Err() == nil {
			f.t.Error("diagnostic dependency was detached from request cancellation")
		}
	}
}
func (f *processingRefusalFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	f.read(ctx, "identity")
	return f.identity, nil
}
func (f *processingRefusalFixture) DownloadPolicy(ctx context.Context) (value.DownloadPolicy, error) {
	f.read(ctx, "policy")
	return f.policy, nil
}
func (f *processingRefusalFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	f.read(ctx, "recovery")
	return artifact.RecoveryProof{}, nil
}

func TestPublicProcessingRefusalKeepsOriginalRequest(t *testing.T) {
	for _, test := range []struct {
		name, cancelAt string
		reads          int
	}{
		{"current", "", 3},
		{"uncapped-parent", "", 3},
		{"already-cancelled", "before", 0},
		{"already-expired", "expired", 0},
		{"cancelled-after-identity", "identity", 1},
		{"cancelled-after-policy", "policy", 2},
		{"cancelled-after-recovery", "recovery", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			until := now.Add(time.Second)
			if test.cancelAt == "expired" {
				until = now.Add(-time.Second)
			}
			var ctx context.Context
			var cancel context.CancelFunc
			if test.name == "uncapped-parent" {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), until)
			}
			defer cancel()
			if test.cancelAt == "before" {
				cancel()
			}
			const root = "00000000-0000-4000-8000-000000000001"
			rev := identity.Revision{UID: root, Generation: 1, Digest: [32]byte{1}}
			principal := identity.Principal{Issuer: "https://identity.invalid", ClientID: "console", Subject: "operator", Kind: identity.Human}
			f := &processingRefusalFixture{t: t, ctx: ctx, cancel: cancel, cancelAt: test.cancelAt,
				identity: identity.Identity{Principal: principal, Policy: rev, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)},
				policy: value.DownloadPolicy{RootID: root, InstallationID: root, RecoveryEpoch: root, Revision: rev,
					ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{},
					Operators:  []value.ProcessingOperator{{Issuer: principal.Issuer, ClientID: principal.ClientID, Kind: "User", ID: principal.Subject}},
					ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}
			s := publicProcessingChanges{root: root, installation: root, policies: f, recovery: f, refused: func(string) {}}
			want := "request"
			if test.cancelAt == "" {
				want = "change"
			}
			if got := s.refusedStep(ctx, f); got != want {
				t.Errorf("refusal step = %q, want %q", got, want)
			}
			if len(f.reads) != test.reads {
				t.Fatalf("dependency reads = %v, want %d before cancellation", f.reads, test.reads)
			}
		})
	}
}
