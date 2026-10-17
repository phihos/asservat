package kubernetes

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerProjectionOperationRejectsCopiedOuterHandle(t *testing.T) {
	for _, method := range []string{"admitted", "after-lock", "apply", "final", "result"} {
		t.Run(method, func(t *testing.T) {
			owner, root, ctx, _ := ownerIdentityOperationTestHandle(t)
			operation := &OwnerProjectionOperation{owner: owner}
			operation.self = operation
			if method == "result" {
				// Local result codec only: no native or SQL authority is supplied.
				owner.phase = ownerIdentityOperationFinal
				operation.resources = contracts.InitialRuntimeResourceSnapshot{State: ownerProjectionTransitionFixture(t), UID: ownerID(4980), ResourceVersion: "2", ValidUntil: owner.original}
				operation.result = OwnerProjectionAdvanceAcknowledged
			}
			phase := owner.phase
			copied := *operation
			var err error
			switch method {
			case "admitted":
				_, err = copied.AdmittedOwnerIdentityRoles(ctx, root)
			case "after-lock":
				_, err = copied.ReadOwnerProjectionAfterLock(ctx, root)
			case "apply":
				err = copied.ApplyOwnerProjection(ctx, root)
			case "final":
				_, err = copied.ReadOwnerProjectionFinal(ctx, root)
			case "result":
				_, err = copied.OwnerProjectionResult(ctx, root)
			}
			if err == nil || owner.phase != phase || owner.active || owner.ctx.Err() != nil {
				t.Fatal("copied outer handle entered or poisoned original operation")
			}
			// Copy rejection must happen before inner admission. The exact original
			// remains usable, including when the copy requested a later phase.
			if method == "result" {
				out, originalErr := operation.OwnerProjectionResult(ctx, root)
				if originalErr != nil || out.Status != OwnerProjectionAdvanceAcknowledged {
					t.Fatal("copy rejection consumed original result", originalErr)
				}
			} else if _, originalErr := operation.AdmittedOwnerIdentityRoles(ctx, root); originalErr != nil {
				t.Fatal("copy rejection consumed original admission", originalErr)
			}
		})
	}
}

func TestOwnerProjectionOperationRejectsSkippedPhasesBeforeNativeOrEffect(t *testing.T) {
	for _, method := range []string{"apply", "final", "result"} {
		t.Run(method, func(t *testing.T) {
			owner, root, ctx, _ := ownerIdentityOperationTestHandle(t)
			operation := &OwnerProjectionOperation{owner: owner}
			operation.self = operation
			// No projection/native adapter is supplied. Phase order must reject before
			// any nil dependency can be reached or an effect can be issued.
			var err error
			switch method {
			case "apply":
				err = operation.ApplyOwnerProjection(ctx, root)
			case "final":
				_, err = operation.ReadOwnerProjectionFinal(ctx, root)
			case "result":
				_, err = operation.OwnerProjectionResult(ctx, root)
			}
			if err == nil || owner.ctx.Err() == nil {
				t.Fatal("projection skipped current/effect/final ordering")
			}
		})
	}
}

func TestOwnerProjectionOperationResultCopiesStateAndCanBeReturnedOnlyOnce(t *testing.T) {
	owner, root, ctx, _ := ownerIdentityOperationTestHandle(t)
	owner.phase = ownerIdentityOperationFinal // local codec/order test, no authority
	state := ownerProjectionTransitionFixture(t)
	operation := &OwnerProjectionOperation{owner: owner, resources: contracts.InitialRuntimeResourceSnapshot{State: state, UID: ownerID(4980), ResourceVersion: "2", ValidUntil: owner.original}, result: OwnerProjectionAdvanceAcknowledged}
	operation.self = operation
	end := owner.original.Add(-time.Second)
	short, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	out, err := operation.OwnerProjectionResult(short, root)
	if err != nil || !out.Snapshot.ValidUntil.Equal(end) {
		t.Fatal("result lost shorter phase bound", err)
	}
	if len(out.Snapshot.State.Objects) == 0 {
		t.Fatal("fixture lacks mutable nested state")
	}
	out.Snapshot.State.Objects[0].OperationID = ownerID(4981)
	if operation.resources.State.Objects[0].OperationID == out.Snapshot.State.Objects[0].OperationID {
		t.Fatal("returned state aliases operation owner")
	}
	if _, err = operation.OwnerProjectionResult(ctx, root); err == nil {
		t.Fatal("completed result phase was reusable")
	}
}

func TestOwnerProjectionOperationChildEndSurvivesLaterOriginalContext(t *testing.T) {
	owner, root, ctx, clock := ownerIdentityOperationTestHandle(t)
	operation := &OwnerProjectionOperation{owner: owner, projection: &OwnerIdentityProjection{root: root}}
	operation.self = operation
	childEnd := owner.original.Add(-2 * time.Second)
	effect, stop, err := operation.originalEffect(ctx, childEnd)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if end, _ := effect.Deadline(); !end.Equal(childEnd) {
		t.Fatal("effect did not preserve original child end")
	}
	owner.phase = ownerIdentityOperationProjectionApplied
	clock.Store(childEnd.Add(time.Nanosecond).UnixNano())
	if err := owner.begin(ctx, root, ownerIdentityOperationProjectionApplied, ownerIdentityOperationReadingFinal); err == nil {
		owner.work.Done()
		t.Fatal("later original context extended child effect end")
	}
}
