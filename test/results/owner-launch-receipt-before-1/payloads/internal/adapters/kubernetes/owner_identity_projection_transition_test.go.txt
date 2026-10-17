package kubernetes

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func ownerProjectionTransitionFixture(t *testing.T) contracts.InitialRuntimeResourceState {
	t.Helper()
	_, state, _, _ := ownerIdentityActivationFixture(t)
	state.OwnerLaunch = nil
	p := *state.OwnerIdentity
	p.Receipt = nil
	p.Configuration = nil
	p.Credentials = nil
	state.OwnerIdentity = &p
	return state
}
func copyOwnerProjectionState(t *testing.T, v contracts.InitialRuntimeResourceState) contracts.InitialRuntimeResourceState {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	out, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func ownerProjectionChild(id int, name string, at time.Time) *contracts.OwnerIdentityObjectAttempt {
	return &contracts.OwnerIdentityObjectAttempt{OperationID: ownerID(id), ClaimedAt: at, Until: at.Add(time.Second), Receipt: &contracts.OwnerIdentityObjectReceipt{Object: contracts.WorkerObjectReference{Name: name, UID: ownerID(id + 10)}, ResourceVersion: "child-1", ObservedAt: at.Add(time.Millisecond)}}
}

func TestOwnerIdentityProjectionCanAdvanceOnlyUntouchedSecondChild(t *testing.T) {
	original := ownerProjectionTransitionFixture(t)
	now := original.OwnerIdentity.ClaimedAt
	first := copyOwnerProjectionState(t, original)
	first.OwnerIdentity.Credentials = ownerProjectionChild(8300, "credentials", now)
	first.OwnerIdentity.Credentials.Receipt = nil
	if !ownerIdentityProjectionTransition(original, first) {
		t.Fatal("first original credentials claim denied")
	}
	uncertain := copyOwnerProjectionState(t, first)
	// Lost CREATE cannot reset/reissue the spent credential child.
	reset := copyOwnerProjectionState(t, uncertain)
	reset.OwnerIdentity.Credentials = nil
	if ownerIdentityProjectionTransition(uncertain, reset) {
		t.Fatal("unknown credentials attempt refunded")
	}
	premature := copyOwnerProjectionState(t, uncertain)
	premature.OwnerIdentity.Configuration = ownerProjectionChild(8301, "configuration", now)
	premature.OwnerIdentity.Configuration.Receipt = nil
	if ownerIdentityProjectionTransition(uncertain, premature) {
		t.Fatal("second object admitted without positive first receipt")
	}
	acknowledged := copyOwnerProjectionState(t, uncertain)
	acknowledged.OwnerIdentity.Credentials = ownerProjectionChild(8300, "credentials", now)
	if !ownerIdentityProjectionTransition(uncertain, acknowledged) {
		t.Fatal("exact original receipt denied")
	}
	// A later call does not renew parent/first dates. Its never-attempted second
	// child gets its one original interval while the journal remains current.
	second := copyOwnerProjectionState(t, acknowledged)
	second.OwnerIdentity.Configuration = ownerProjectionChild(8301, "configuration", now.Add(10*time.Second))
	second.OwnerIdentity.Configuration.Receipt = nil
	if !ownerIdentityProjectionTransition(acknowledged, second) {
		t.Fatal("untouched second child cannot progress")
	}
	if !equalJSON(second.OwnerIdentity.Credentials, acknowledged.OwnerIdentity.Credentials) || second.OwnerIdentity.Until != original.OwnerIdentity.Until {
		t.Fatal("original interval changed")
	}
	replaced := copyOwnerProjectionState(t, second)
	replaced.OwnerIdentity.Credentials.OperationID = ownerID(8399)
	if ownerIdentityProjectionTransition(second, replaced) {
		t.Fatal("original credential attempt replaced")
	}
	secondAck := copyOwnerProjectionState(t, second)
	secondAck.OwnerIdentity.Configuration.Receipt = ownerProjectionChild(8301, "configuration", now.Add(10*time.Second)).Receipt
	if !ownerIdentityProjectionTransition(second, secondAck) {
		t.Fatal("second positive receipt denied")
	}
	complete := copyOwnerProjectionState(t, secondAck)
	c, f := complete.OwnerIdentity.Credentials.Receipt, complete.OwnerIdentity.Configuration.Receipt
	complete.OwnerIdentity.Receipt = &contracts.OwnerIdentityProjectionReceipt{Credentials: c.Object, CredentialsResourceVersion: c.ResourceVersion, Configuration: f.Object, ConfigurationResourceVersion: f.ResourceVersion, ObservedAt: f.ObservedAt}
	if !ownerIdentityProjectionTransition(secondAck, complete) {
		t.Fatal("joint exact receipt denied")
	}
	forged := copyOwnerProjectionState(t, complete)
	forged.OwnerIdentity.Receipt.Credentials.UID = ownerID(8388)
	if ownerIdentityProjectionTransition(secondAck, forged) {
		t.Fatal("joint receipt substituted child")
	}
	if ownerIdentityProjectionTransition(complete, complete) {
		t.Fatal("completed projection grants another mutation")
	}
}
func TestOwnerIdentityProjectionAndLaunchKeepAllSiblingState(t *testing.T) {
	old := ownerProjectionTransitionFixture(t)
	next := copyOwnerProjectionState(t, old)
	next.OwnerIdentity.Credentials = ownerProjectionChild(8400, "credentials", old.OwnerIdentity.ClaimedAt)
	next.OwnerIdentity.Credentials.Receipt = nil
	for name, change := range map[string]func(*contracts.InitialRuntimeResourceState){
		"inventory": func(v *contracts.InitialRuntimeResourceState) { v.Objects[0].OperationID = ownerID(8480) },
		"binding":   func(v *contracts.InitialRuntimeResourceState) { v.BindingDigest = preparationDigest("other") },
		"end":       func(v *contracts.InitialRuntimeResourceState) { v.Until = v.Until.Add(time.Second) },
		"parent-public-input": func(v *contracts.InitialRuntimeResourceState) {
			v.OwnerIdentity.PublicDigest = preparationDigest("changed")
		},
		"capacity": func(v *contracts.InitialRuntimeResourceState) {
			v.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{OperationID: ownerID(8481)}
		},
		"cleanup": func(v *contracts.InitialRuntimeResourceState) {
			v.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{OperationID: ownerID(8482)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := copyOwnerProjectionState(t, next)
			change(&x)
			if ownerIdentityProjectionTransition(old, x) {
				t.Fatal("unrelated state rewritten")
			}
		})
	}
	_, complete, _, _ := ownerIdentityActivationFixture(t)
	pending := copyOwnerProjectionState(t, complete)
	pending.OwnerLaunch.Receipt = nil
	if !ownerIdentityLaunchTransition(pending, complete) {
		t.Fatal("exact positive launch receipt denied")
	}
	replacement := copyOwnerProjectionState(t, pending)
	replacement.OwnerLaunch.OperationID = ownerID(8483)
	if ownerIdentityLaunchTransition(pending, replacement) {
		t.Fatal("uncertain launch replaced")
	}
	if ownerIdentityProjectionTransition(pending, next) {
		t.Fatal("projection reopened after launch claim")
	}
}
