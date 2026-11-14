package bootstrap

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type installedObservationFixture struct {
	base                            *runtimeFixture
	pin                             value.OwnerObservationPin
	binding                         value.OwnerBinding
	cert                            value.OwnerCertificate
	enrollment                      value.OwnerEnrollment
	mode                            string
	httpCalls, tokenReads           atomic.Int32
	candidateLegacy, candidateOpted atomic.Int32
	bound                           time.Time
	entered, release                chan struct{}
}

func (f *installedObservationFixture) ReadContextStartOwners(context.Context) (value.APIContextOwnerCandidates, error) {
	f.candidateLegacy.Add(1)
	if strings.HasPrefix(f.mode, "opted-") {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	return f.candidateValues(), nil
}
func (f *installedObservationFixture) candidateValues() value.APIContextOwnerCandidates {
	now := time.Now()
	if f.mode == "expired-before-token" {
		f.bound = now.Add(80 * time.Millisecond)
	}
	owners := []value.OwnerBinding{f.binding}
	if f.mode == "candidate-exclusion" {
		owners[0].ProcessEpoch = "22222222-2222-4222-8222-222222222222"
	}
	return value.APIContextOwnerCandidates{Pool: f.pin.Pool, Owners: owners, ObservedAt: now, ValidUntil: identity.Earlier(now.Add(5*time.Second), f.bound)}
}
func (f *installedObservationFixture) ReadOwnerObservationCandidates(context.Context) (value.APIContextOwnerCandidates, error) {
	f.candidateOpted.Add(1)
	if f.mode == "opted-unavailable" {
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	}
	v := f.candidateValues()
	v.Owners = nil
	for i := 1; i <= 16; i++ {
		b := f.binding
		b.ProcessEpoch = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		v.Owners = append(v.Owners, b)
	}
	v.Owners = append(v.Owners, f.binding)
	if f.mode == "opted-changed-limit" {
		v.Pool.NativeCandidateLimit++
	}
	if f.mode == "opted-overflow" {
		b := f.binding
		b.ProcessEpoch = "22222222-2222-4222-8222-222222222222"
		v.Owners = append(v.Owners, b)
	}
	return v, nil
}
func (f *installedObservationFixture) configuration() value.OwnerConfigurationObservation {
	now := time.Now()
	return value.OwnerConfigurationObservation{Configuration: f.base.configuration.Clone(), ObservedAt: now, FreshUntil: identity.Earlier(now.Add(5*time.Second), f.bound)}
}
func (f *installedObservationFixture) ReadOwnerRegistration(_ context.Context, c value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	if c != f.cert || f.mode == "registry-denial" || f.mode == "revoked-after-response" && f.httpCalls.Load() > 0 {
		return value.OwnerRegistrationObservation{}, value.ErrUnavailable
	}
	o := f.configuration()
	if f.mode == "wrong-source" {
		o.Configuration.Revision.UID = "22222222-2222-4222-8222-222222222222"
	}
	if f.mode == "source-revision-during-response" && f.httpCalls.Load() > 0 {
		o.Configuration.Revision.Generation++
	}
	return value.OwnerRegistrationObservation{Certificate: c, Enrollment: f.enrollment, Configuration: o, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *installedObservationFixture) CurrentOwnerRoute(_ context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
	if b != f.binding || f.mode == "not-ready" {
		return value.OwnerRoute{}, value.ErrUnavailable
	}
	o := f.configuration()
	return value.OwnerRoute{Configuration: o, Endpoint: value.OwnerEndpoint{Pool: f.pin.Pool, Binding: b, Pod: f.enrollment.Pod, ReplicaSetUID: f.enrollment.ReplicaSetUID, Addresses: []string{"10.0.0.5"}, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *installedObservationFixture) ReadOwnerProtection(_ context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
	o := f.configuration()
	d := f.pin.ProtectionDigest
	if f.mode == "wrong-guard" {
		d[0]++
	}
	return value.OwnerProtection{Pool: p, Digest: d, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *installedObservationFixture) ObserveOwnerWorkload(ctx context.Context, b value.OwnerBinding, pod string) (value.OwnerObservationWorkload, error) {
	if f.mode == "expired-before-token" {
		<-ctx.Done()
		return value.OwnerObservationWorkload{}, value.ErrUnavailable
	}
	if f.entered != nil {
		close(f.entered)
		<-ctx.Done()
		<-f.release
		return value.OwnerObservationWorkload{}, value.ErrUnavailable
	}
	if b != f.binding || pod != f.enrollment.Pod || f.mode == "wrong-template" {
		return value.OwnerObservationWorkload{}, value.ErrUnavailable
	}
	o := f.configuration()
	return value.OwnerObservationWorkload{Pin: f.pin, Binding: b, Pod: pod, ReplicaSetUID: f.enrollment.ReplicaSetUID, WorkloadDigest: artifact.Digest{7}, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}, nil
}
func (f *installedObservationFixture) ReadClusterObservationToken(context.Context) ([]byte, error) {
	f.tokenReads.Add(1)
	return []byte("synthetic-projected-observation-token"), nil
}

func installedObservationRequest() value.ClusterObservationRequest {
	now := time.Now()
	return value.ClusterObservationRequest{ID: runtimeID, Challenge: runtimeID, RootID: runtimeID, ClusterID: runtimeID, Purpose: value.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}
}
