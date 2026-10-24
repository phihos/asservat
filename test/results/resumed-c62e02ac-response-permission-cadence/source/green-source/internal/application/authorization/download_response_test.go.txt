package authorization

import (
	"context"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// These are genuinely new short source observations at each simulated instant.
// The response must never rewrite the old projection's original freshness.
func currentDownloadResponseFacts(f *downloadAuthorityFixture, now time.Time) {
	f.now = now
	f.i.VerifiedAt, f.i.ValidUntil = now, now.Add(5*time.Second)
	f.p.ObservedAt, f.p.FreshUntil = now, now.Add(5*time.Second)
	f.p.DeniesObservedAt, f.p.DeniesFreshUntil = now, now.Add(5*time.Second)
	for j := range f.p.Allows {
		f.p.Allows[j].ObservedAt, f.p.Allows[j].FreshUntil = now, now.Add(5*time.Second)
	}
	for j := range f.p.Denies {
		f.p.Denies[j].ObservedAt, f.p.Denies[j].FreshUntil = now, now.Add(5*time.Second)
	}
	f.record.ObservedAt, f.record.ValidUntil = now, now.Add(5*time.Second)
	f.resolved.ValidUntil = now.Add(5 * time.Second)
	f.resolved.Proof.ObservedAt, f.resolved.Proof.ValidUntil = now, now.Add(5*time.Second)
	f.environment.ObservedAt, f.environment.ValidUntil = now, now.Add(5*time.Second)
}

type responsePermissionReader func(context.Context, value.Target) (value.Projection, error)

func (f responsePermissionReader) Permissions(ctx context.Context, target value.Target) (value.Projection, error) {
	return f(ctx, target)
}

func TestDownloadResponsePermissionCadenceStartsBeforeIO(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	start := f.now
	service.Permissions = responsePermissionReader(func(ctx context.Context, target value.Target) (value.Projection, error) {
		if f.policyReads == 0 {
			currentDownloadResponseFacts(f, start.Add(2*time.Second))
		}
		return f.Permissions(ctx, target)
	})
	owner, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current := credentialIdentity{f, "synthetic"}
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
		t.Fatal(err)
	}
	currentDownloadResponseFacts(f, start.Add(29*time.Second))
	if a, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil || f.policyReads != 2 || !a.ValidUntil.Equal(start.Add(30*time.Second)) {
		t.Fatal("response cadence renewed from completed source I/O", a.ValidUntil, f.policyReads, err)
	}
	currentDownloadResponseFacts(f, start.Add(30*time.Second))
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil || f.policyReads != 4 {
		t.Fatal("exact original cutoff did not reconstruct permission", f.policyReads, err)
	}
}

func TestDownloadResponseCancelledRefreshCannotBeRetried(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	entered := make(chan struct{})
	service.Permissions = responsePermissionReader(func(ctx context.Context, target value.Target) (value.Projection, error) {
		if f.policyReads == 2 {
			close(entered)
			<-ctx.Done()
			return value.Projection{}, ctx.Err()
		}
		return f.Permissions(ctx, target)
	})
	owner, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current := credentialIdentity{f, "synthetic"}
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
		t.Fatal(err)
	}
	currentDownloadResponseFacts(f, f.now.Add(30*time.Second))
	call, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := owner.CheckDownloadCurrent(call, current, scope); done <- err }()
	<-entered
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled refresh succeeded")
	}
	// Replace the blocked test reader only after it has joined. A terminal owner
	// must refuse before calling the healthy source through this same object.
	owner.service.Permissions = f
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil || f.policyReads != 2 {
		t.Fatal("cancelled refresh revived the old response", f.policyReads, err)
	}
}

func TestDownloadResponseCloseCancelsAndJoinsBlockedRefresh(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	service.Permissions = responsePermissionReader(func(ctx context.Context, target value.Target) (value.Projection, error) {
		if f.policyReads == 2 {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-release
			return value.Projection{}, ctx.Err()
		}
		return f.Permissions(ctx, target)
	})
	owner, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	current := credentialIdentity{f, "synthetic"}
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
		t.Fatal(err)
	}
	currentDownloadResponseFacts(f, f.now.Add(30*time.Second))
	done := make(chan error, 1)
	go func() { _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); done <- err }()
	<-entered
	closed := make(chan struct{})
	go func() { owner.Close(); close(closed) }()
	<-cancelled
	select {
	case <-closed:
		t.Error("Close returned before the blocked reader joined")
	default:
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("closed refresh succeeded")
	}
	<-closed
	owner.Close()
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil {
		t.Fatal("closed observation remained usable")
	}
}

func TestDownloadResponseFailedSafetyReadDoesNotSeedPermissionObservation(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	owner, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	f.fail = "environment"
	current := credentialIdentity{f, "synthetic"}
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil {
		t.Fatal("environment failure accepted")
	}
	reads := f.policyReads
	f.fail = ""
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil || f.policyReads != reads {
		t.Fatal("failed full authority seeded or revived response", f.policyReads, err)
	}
	fresh, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.CheckDownloadCurrent(t.Context(), current, scope); err != nil || f.policyReads != reads+2 {
		t.Fatal("new response did not independently reconstruct permission", f.policyReads, err)
	}
}

func TestDownloadResponseOwnsClaimAndAudienceSlices(t *testing.T) {
	for _, mutation := range []string{"claims", "audience"} {
		t.Run(mutation, func(t *testing.T) {
			f, service, scope := newDownloadAuthorityFixture()
			owner, err := service.NewDownloadResponse(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			current := credentialIdentity{f, "synthetic"}
			if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
				t.Fatal(err)
			}
			currentDownloadResponseFacts(f, f.now.Add(time.Second))
			if mutation == "claims" {
				f.i.Groups[0] = "removed"
			} else {
				f.record.Audience[0].AssignmentID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			}
			if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil {
				t.Fatal("source slice mutation changed the retained decision")
			}
		})
	}
}

func TestDownloadResponsePermissionReconstructionCadence(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	start := f.now
	owned, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	for _, step := range []struct {
		at    time.Duration
		reads int
	}{
		{0, 2}, {5 * time.Second, 2}, {10 * time.Second, 2},
		{30*time.Second - time.Nanosecond, 2}, {30 * time.Second, 4}, {35 * time.Second, 4},
	} {
		currentDownloadResponseFacts(f, start.Add(step.at))
		raw := f.p
		a, err := owned.CheckDownloadCurrent(t.Context(), credentialIdentity{f, "synthetic"}, scope)
		if err != nil || !a.Valid(f.now) || a.ValidUntil.After(f.now.Add(5*time.Second)) {
			t.Fatalf("at %s: invalid short authority: %v", step.at, err)
		}
		if f.policyReads != step.reads {
			t.Errorf("at %s: permission reads=%d want=%d", step.at, f.policyReads, step.reads)
		}
		if !f.p.FreshUntil.Equal(raw.FreshUntil) || !f.p.DeniesFreshUntil.Equal(raw.DeniesFreshUntil) {
			t.Fatal("ordinary observation rewrote source freshness")
		}
		if step.at < 30*time.Second && a.ValidUntil.After(start.Add(30*time.Second)) {
			t.Fatal("short authority passed original reconstruction cutoff")
		}
	}
	if f.catalogReads != 6 || f.retentionReads != 6 || f.environmentReads != 6 {
		t.Fatal("response reuse skipped current safety reads")
	}
}

func TestDownloadResponsePermissionOwnerIsolationAndClose(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	currentDownloadResponseFacts(f, f.now)
	first, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	current := credentialIdentity{f, "synthetic"}
	for _, owner := range []*DownloadResponseAuthority{first, second} {
		if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
			t.Fatal(err)
		}
	}
	if f.policyReads != 4 {
		t.Fatal("different responses shared permission reconstruction", f.policyReads)
	}
	first.Close()
	if _, err := first.CheckDownloadCurrent(t.Context(), current, scope); err == nil || f.policyReads != 4 {
		t.Fatal("closed response retained authority or did I/O", err)
	}
	changed := scope
	changed.ArtifactID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := second.CheckDownloadCurrent(t.Context(), current, changed); err == nil || f.policyReads != 4 {
		t.Fatal("response reused different scope", err)
	}
	if _, err := service.CheckDownloadCurrent(t.Context(), current, scope); err != nil || f.policyReads != 6 {
		t.Fatal("ordinary preparation inherited response observation", err, f.policyReads)
	}
}

func TestDownloadResponseChangedIdentityClaimsRecheckBeforeCatalog(t *testing.T) {
	for _, change := range []string{"groups", "scopes", "policy", "principal", "reordered-sets"} {
		t.Run(change, func(t *testing.T) {
			f, service, scope := newDownloadAuthorityFixture()
			f.i.Groups = append(f.i.Groups, "other")
			currentDownloadResponseFacts(f, f.now)
			owner, err := service.NewDownloadResponse(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			current := credentialIdentity{f, "synthetic"}
			if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
				t.Fatal(err)
			}
			currentDownloadResponseFacts(f, f.now.Add(time.Second))
			switch change {
			case "groups":
				f.i.Groups = []string{"removed"}
			case "scopes":
				f.i.Scopes = []string{"evidence:read"}
			case "policy":
				f.i.Policy.Generation++
				f.p.Allows = nil
			case "principal":
				f.i.Principal.ClientID = "different-client"
			case "reordered-sets":
				slices.Reverse(f.i.Groups)
				slices.Reverse(f.i.Scopes)
			}
			_, err = owner.CheckDownloadCurrent(t.Context(), current, scope)
			if change == "reordered-sets" {
				if err != nil || f.policyReads != 2 || f.catalogReads != 2 {
					t.Fatal("order changed identity set or reconstruction", err, f.policyReads, f.catalogReads)
				}
			} else if err == nil || f.catalogReads != 1 {
				t.Fatal("changed identity reached catalog before fresh eligibility", err, f.catalogReads)
			}
		})
	}
}

func TestDownloadResponseFailedPermissionRefreshIsTerminal(t *testing.T) {
	f, service, scope := newDownloadAuthorityFixture()
	currentDownloadResponseFacts(f, f.now)
	owner, err := service.NewDownloadResponse(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current := credentialIdentity{f, "synthetic"}
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil {
		t.Fatal(err)
	}
	currentDownloadResponseFacts(f, f.now.Add(30*time.Second))
	f.policyError = true
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil || f.catalogReads != 1 {
		t.Fatal("failed renewal used stale entitlement", err)
	}
	reads := f.policyReads
	f.policyError = false
	if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil || f.policyReads != reads {
		t.Fatal("failed response was revived instead of requiring a new request", err, f.policyReads)
	}
}

func TestDownloadResponseRetainedAudienceAndSafetyChangesStillDeny(t *testing.T) {
	for _, change := range []string{"audience", "version", "retention", "recovery", "identity-expiry", "cancel"} {
		t.Run(change, func(t *testing.T) {
			f, service, scope := newDownloadAuthorityFixture()
			currentDownloadResponseFacts(f, f.now)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			owner, err := service.NewDownloadResponse(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			current := credentialIdentity{f, "synthetic"}
			if _, err := owner.CheckDownloadCurrent(ctx, current, scope); err != nil {
				t.Fatal(err)
			}
			currentDownloadResponseFacts(f, f.now.Add(time.Second))
			switch change {
			case "audience":
				f.record.Audience = []artifact.AudienceAssignment{}
			case "version":
				f.record.Version[0]++
			case "retention":
				f.resolved.ExpiresAt = f.now
			case "recovery":
				f.environment.RecoveryEpoch = ""
			case "identity-expiry":
				f.i.ValidUntil = f.now
			case "cancel":
				cancel()
			}
			if _, err := owner.CheckDownloadCurrent(ctx, current, scope); err == nil {
				t.Fatal("ordinary cadence weakened a current safety check")
			}
		})
	}
}
