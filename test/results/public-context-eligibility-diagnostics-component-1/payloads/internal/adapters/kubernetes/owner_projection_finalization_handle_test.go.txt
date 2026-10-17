package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// Pure opaque-handle order/lifetime tests. The root here is intentionally not
// a real SQL/native authority, so no network-capable phase can be entered.
func projectionFinalizationHandle(t *testing.T) (*OwnerProjectionFinalization, *OwnerIdentityRoleRoot, context.Context, *atomic.Int64) {
	t.Helper()
	_, root, original, clock := ownerIdentityOperationTestHandle(t)
	root.ownerOperation = nil
	p := &ProviderOwnerProjection{projection: &OwnerIdentityProjection{root: root}, split: true}
	p.self = p
	root.splitProjection = p
	state := ownerProjectionTransitionFixture(t)
	end, _ := original.Deadline()
	pending := &ownerProjectionPending{controller: p, caller: original, step: ownerProjectionParent, semanticVersion: 1, resources: contracts.InitialRuntimeResourceSnapshot{State: state, UID: ownerID(9980), ResourceVersion: "4", ValidUntil: end}}
	f := &OwnerProjectionFinalization{controller: p, pending: pending, until: end}
	f.self = f
	call, cancel := context.WithCancel(context.WithValue(original, ownerProjectionFinalizationKey{}, f))
	f.ctx, f.cancel = call, cancel
	t.Cleanup(f.closeAndJoin)
	return f, root, call, clock
}
func TestOwnerProjectionFinalizerRejectsCopiesDetachedSkippedAndRepeatedPhases(t *testing.T) {
	for _, mode := range []string{"zero", "copied", "foreign-root", "detached", "cancelled", "skipped-current", "skipped-result", "repeated-admission", "version-before-admission"} {
		t.Run(mode, func(t *testing.T) {
			f, root, ctx, _ := projectionFinalizationHandle(t)
			target := f
			var err error
			switch mode {
			case "zero":
				target = &OwnerProjectionFinalization{}
			case "copied":
				target = &OwnerProjectionFinalization{self: f, controller: f.controller, pending: f.pending, ctx: f.ctx, until: f.until}
			case "foreign-root":
				root = &OwnerIdentityRoleRoot{}
			case "detached":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), f.until)
				defer cancel()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "skipped-current":
				_, err = f.ReadOwnerProjectionFinalizationCurrent(ctx, root)
			case "skipped-result":
				_, err = f.OwnerProjectionFinalizationResult(ctx, root)
			case "repeated-admission":
				if _, _, err = f.AdmitOwnerProjectionFinalization(ctx, root); err != nil {
					t.Fatal(err)
				}
			case "version-before-admission":
				err = f.MatchOwnerProjectionSemanticVersion(ctx, root, 1)
			}
			if mode != "skipped-current" && mode != "skipped-result" && mode != "version-before-admission" {
				_, _, err = target.AdmitOwnerProjectionFinalization(ctx, root)
			}
			if err == nil {
				t.Fatal("invalid finalizer entered a phase")
			}
			if mode == "copied" {
				if _, _, err = f.AdmitOwnerProjectionFinalization(ctx, root); err != nil {
					t.Fatal("copy consumed original admission", err)
				}
			}
		})
	}
}
func TestOwnerProjectionFinalizerRetainsShorterOriginalDeadline(t *testing.T) {
	f, root, ctx, clock := projectionFinalizationHandle(t)
	end := f.until.Add(-time.Second)
	short, stop := context.WithDeadline(ctx, end)
	defer stop()
	_, until, err := f.AdmitOwnerProjectionFinalization(short, root)
	if err != nil || !until.Equal(end) {
		t.Fatal("admission lost shorter context", err)
	}
	if err = f.MatchOwnerProjectionSemanticVersion(short, root, 1); err != nil {
		t.Fatal(err)
	}
	clock.Store(end.Add(time.Nanosecond).UnixNano())
	if _, err = f.ReadOwnerProjectionFinalizationAfterLock(ctx, root); err == nil {
		t.Fatal("wider context restored original cutoff")
	}
}
func TestOwnerProjectionFinalizerRequiresExactSemanticVersionOnce(t *testing.T) {
	f, root, ctx, _ := projectionFinalizationHandle(t)
	if _, _, err := f.AdmitOwnerProjectionFinalization(ctx, root); err != nil {
		t.Fatal(err)
	}
	if err := f.MatchOwnerProjectionSemanticVersion(ctx, root, 2); err == nil {
		t.Fatal("semantic ABA accepted")
	}
	if f.versionMatched.Load() {
		t.Fatal("mismatch replaced original version")
	}
	if err := f.MatchOwnerProjectionSemanticVersion(ctx, root, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.MatchOwnerProjectionSemanticVersion(ctx, root, 1); err == nil {
		t.Fatal("version comparison repeated")
	}
}
func TestOwnerProjectionFinalizerCloseJoinsAdmittedWork(t *testing.T) {
	f, root, ctx, _ := projectionFinalizationHandle(t)
	if err := f.enter(ctx, root, 0, 10); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	finish := func() { once.Do(f.work.Done) }
	defer finish()
	closed := make(chan struct{})
	go func() { f.closeAndJoin(); close(closed) }()
	defer func() { finish(); <-closed }()
	select {
	case <-f.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("close did not cancel operation")
	}
	select {
	case <-closed:
		t.Fatal("close did not join admitted work")
	default:
	}
	if _, _, err := f.AdmitOwnerProjectionFinalization(ctx, root); err == nil {
		t.Fatal("closing handle admitted more work")
	}
	finish()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not finish join")
	}
}
func TestOwnerProjectionFinalizerResultIsOneUseAndCopiesState(t *testing.T) {
	f, root, ctx, _ := projectionFinalizationHandle(t)
	f.current.retained.resources = f.pending.resources
	f.phase.Store(3) // local result codec only; no source/SQL authority supplied
	out, err := f.OwnerProjectionFinalizationResult(ctx, root)
	if err != nil || out.Status != OwnerProjectionAdvanceAcknowledged {
		t.Fatal(err)
	}
	out.Snapshot.State.Objects[0].OperationID = "caller-copy"
	if f.current.retained.resources.State.Objects[0].OperationID == "caller-copy" {
		t.Fatal("returned state aliases handle")
	}
	if _, err = f.OwnerProjectionFinalizationResult(ctx, root); err == nil {
		t.Fatal("result reusable")
	}
}
