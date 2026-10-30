// Package planning compiles immutable scopes without acquiring evidence.
package planning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

// The initial qualified path is exactly this recipe plus the independently
// pinned projection definition. It is not a general kubernetesSnapshot adapter.
const ContextRecipeName = "builtin-pod-status-v1"
const ContextRecipeSpec = `{"description":"Bounded pod status without workload configuration or free-text messages.","actions":[{"id":"pod-status","kind":"kubernetesSnapshot","parameters":{"include":["pod"]},"dependsOn":[],"required":true,"impact":"observe","limits":{"maxBytes":4096,"timeout":"5s"},"executionMode":"onTrigger"}],"maxTotalBytes":4096,"maxDuration":"5s"}`

type source struct {
	ClusterID    string `json:"clusterID"`
	NamespaceUID string `json:"namespaceUID"`
	ResourceUID  string `json:"resourceUID"`
}
type principal struct {
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	ClientID string `json:"clientID"`
	Kind     string `json:"identityType"`
}
type workload struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}
type target struct {
	Namespace string   `json:"namespace"`
	Workload  workload `json:"workloadRef"`
	MaxPods   int      `json:"maxPods"`
	Selection string   `json:"selection"`
	Adoption  string   `json:"adoption"`
}
type recipeRef struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type captureSpec struct {
	Target    target    `json:"target"`
	Recipe    recipeRef `json:"recipeRef"`
	CaseID    string    `json:"caseID,omitempty"`
	Deadline  string    `json:"deadline"`
	Retention string    `json:"retention"`
}
type collection struct {
	Kind string      `json:"kind"`
	Spec captureSpec `json:"spec"`
}
type dependency struct {
	Role   string `json:"role"`
	Digest string `json:"digest"`
}
type podBinding struct {
	ExecutionClass artifact.ContextExecutionClass `json:"executionClass,omitempty"`
	PodUID         string                         `json:"podUID"`
	NodeUID        string                         `json:"nodeUID,omitempty"`
	NodeBootID     string                         `json:"nodeBootID,omitempty"`
}
type policyRef struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
}
type effectiveRetention struct {
	ActionID       string      `json:"actionID"`
	PurposeRef     string      `json:"purposeRef"`
	PrivacyClass   string      `json:"privacyClass"`
	EvidenceType   string      `json:"evidenceType"`
	Requested      int64       `json:"requestedAgeSeconds"`
	Maximum        int64       `json:"maximumAgeSeconds"`
	DeletionBudget int64       `json:"deletionBudgetSeconds"`
	Policies       []policyRef `json:"policyRefs"`
}
type scope struct {
	Version      string               `json:"schemaVersion"`
	Source       source               `json:"source"`
	Executor     principal            `json:"executor"`
	Collection   collection           `json:"collection"`
	Dependencies []dependency         `json:"dependencies"`
	Pods         []podBinding         `json:"podBindings"`
	Retention    []effectiveRetention `json:"effectiveRetention"`
}

func hexDigest(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
func canonical(b []byte) ([]byte, artifact.Digest, error) {
	c := jsontext.Value(bytes.Clone(b))
	if c.Canonicalize() != nil {
		return nil, artifact.Digest{}, value.ErrInvalid
	}
	return c, artifact.Digest(sha256.Sum256(c)), nil
}
func RecipeDigest() artifact.Digest { _, d, _ := canonical([]byte(ContextRecipeSpec)); return d }
func ProjectionDigest() artifact.Digest {
	return artifact.Digest(sha256.Sum256([]byte(artifact.ContextProjectionDefinition)))
}

// CompileContext only accepts independently resolved inputs. Caller fields such
// as reason, sharing, approval references and idempotency keys cannot enter this
// execution digest. The capture identity and original deadline always do.
func CompileContext(in value.ContextInput, now time.Time) (value.ContextPlan, error) {
	if in.Snapshot != nil {
		return compileSourceSnapshotContext(in, now)
	}
	if in.Recorder != nil {
		return compileRecorderContext(in, now)
	}
	bad := func() (value.ContextPlan, error) { return value.ContextPlan{}, value.ErrInvalid }
	if !authorization.UUID(in.CaptureID) || (in.CaseID != "" && !authorization.UUID(in.CaseID)) || !in.Executor.Valid() || !in.Target.Valid(now) || !in.Capability.Valid(now) || in.Target.ExecutionClass != in.Capability.ExecutionClass || in.Capability.ProjectionDigest != ProjectionDigest() || in.Deadline.Nanosecond()%1000 != 0 || !now.Before(in.Deadline) || in.Deadline.After(now.Add(5*time.Minute)) {
		return bad()
	}
	r := in.Retention
	if r.Proof != (artifact.RetentionProof{}) && (!r.Proof.Valid(now) || !r.Proof.Matches(r.Proof.RootID, r.Target.ClusterID, r.Target.NamespaceUID, r.Target.WorkloadUID, r.Target.PodUID) || r.Proof.Policy != r.PolicyRevision || r.ValidUntil.After(r.Proof.ValidUntil)) {
		return bad()
	}
	if r.Target != in.Target.Target() || !r.PolicyRevision.Valid() || !now.Before(r.ValidUntil) || r.ValidUntil.After(now.Add(60*time.Second)) || r.PrivacyClass != "potentialPersonalData" || r.EvidenceType != "context" || !r.Deadlines.Valid() || r.AnchorAt.After(now) || !identity.Text(r.PurposeRef, 128) || len(r.Policies) < 1 || len(r.Policies) > 64 {
		return bad()
	}
	// For this acquired, single-source profile, the verifier's initial retention
	// arithmetic must agree exactly. Parent-derived formats need their own compiler.
	if r.RequestedSeconds < 1 || r.RequestedSeconds > 315360000 || r.MaximumSeconds < 1 || r.MaximumSeconds > 315360000 || r.DeletionBudgetSeconds < 1 || r.DeletionBudgetSeconds > 86400 || r.DeletionBudgetSeconds >= r.MaximumSeconds {
		return bad()
	}
	expected := r.AnchorAt.Add(time.Duration(min(r.RequestedSeconds, r.MaximumSeconds-r.DeletionBudgetSeconds)) * time.Second)
	if !r.ExpiresAt.Equal(expected) || !r.DeleteBy.Equal(expected.Add(time.Duration(r.DeletionBudgetSeconds)*time.Second)) || !now.Before(r.ExpiresAt) {
		return bad()
	}
	deps := []dependency{{"collectionCeiling", hexDigest(artifact.Digest(in.Capability.Revision.Digest))}, {"collector", hexDigest(in.Capability.CollectorImageDigest)}, {"projection", hexDigest(in.Capability.ProjectionDigest)}, {"recipe", hexDigest(RecipeDigest())}}
	seenUID := map[string]bool{}
	seenDigest := map[artifact.Digest]bool{}
	refs := make([]policyRef, 0, len(r.Policies))
	for _, p := range r.Policies {
		if !identity.Text(p.UID, 64) || p.Generation < 1 || p.Generation > 2147483647 || p.Digest == (artifact.Digest{}) || seenUID[p.UID] {
			return bad()
		}
		seenUID[p.UID] = true
		// Equal definitions in independently pinned policies need one dependency
		// digest; all source identities remain in the accepted retention record.
		if !seenDigest[p.Digest] {
			deps = append(deps, dependency{"retention", hexDigest(p.Digest)})
			seenDigest[p.Digest] = true
		}
		refs = append(refs, policyRef{p.UID, p.Generation, hexDigest(p.Digest)})
	}
	if len(deps) > 64 {
		return bad()
	}
	slices.SortFunc(refs, func(a, b policyRef) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	slices.SortFunc(deps, func(a, b dependency) int {
		if a.Role < b.Role {
			return -1
		}
		if a.Role > b.Role {
			return 1
		}
		if a.Digest < b.Digest {
			return -1
		}
		if a.Digest > b.Digest {
			return 1
		}
		return 0
	})
	q := in.Target.Request
	api := "apps/v1"
	if q.Workload.Kind == "Pod" {
		api = "v1"
	}
	s := scope{Version: "collection-scope/v1", Source: source{q.ClusterID, q.Namespace.UID, in.CaptureID}, Executor: principal{in.Executor.Issuer, in.Executor.Subject, in.Executor.ClientID, string(in.Executor.Kind)}, Collection: collection{"DebugCapture", captureSpec{target{q.Namespace.Name, workload{api, q.Workload.Kind, q.Workload.Name, q.Workload.UID}, 1, "allWithinLimit", "pinUID"}, recipeRef{ContextRecipeName, hexDigest(RecipeDigest())}, in.CaseID, in.Deadline.UTC().Format(time.RFC3339Nano), strconv.FormatInt(r.RequestedSeconds, 10) + "s"}}, Dependencies: deps, Pods: []podBinding{{ExecutionClass: in.Target.ExecutionClass, PodUID: q.PodUID, NodeUID: in.Target.NodeUID, NodeBootID: in.Target.NodeBootID}}}
	s.Retention = []effectiveRetention{{"pod-status", r.PurposeRef, r.PrivacyClass, r.EvidenceType, r.RequestedSeconds, r.MaximumSeconds, r.DeletionBudgetSeconds, refs}}
	b, err := json.Marshal(s)
	if err != nil {
		return bad()
	}
	b, d, err := canonical(b)
	if err != nil {
		return bad()
	}
	until := identity.Earlier(in.Target.FreshUntil, in.Capability.FreshUntil)
	until = identity.Earlier(until, r.ValidUntil)
	until = identity.Earlier(until, in.Deadline)
	// Defensive copies keep caller-owned slices from changing the frozen plan.
	in.Retention.Policies = slices.Clone(in.Retention.Policies)
	return value.ContextPlan{Input: in, CanonicalScope: b, ScopeDigest: d, RecipeDigest: RecipeDigest(), ValidUntil: until, CompiledAt: now}, nil
}

// VerifyFrozenContextPlan validates immutable content for original-key lookup.
// Expired observations may identify an old request but cannot start new work.
func VerifyFrozenContextPlan(plan value.ContextPlan) bool {
	return !plan.CompiledAt.IsZero() && VerifyContextPlan(plan, plan.CompiledAt)
}

func VerifyContextPlan(plan value.ContextPlan, now time.Time) bool {
	fresh, err := CompileContext(plan.Input, now)
	return err == nil && fresh.ScopeDigest == plan.ScopeDigest && fresh.RecipeDigest == plan.RecipeDigest && bytes.Equal(fresh.CanonicalScope, plan.CanonicalScope) && fresh.ValidUntil.Equal(plan.ValidUntil)
}
