package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"fmt"
	"testing"
	"time"
)

func fixture() (identity.Identity, Projection, Retained, time.Time) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	revision := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	i := identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "non-lead-developer", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read", "evidence:capture", "evidence:download"}, Groups: []string{"team-a"}, Policy: revision, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	target := Target{"11111111-1111-1111-1111-111111111111", "namespace-uid", "workload-uid", "pod-uid"}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: i.Principal.Issuer, SubjectID: "team-a", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-uid", BasisDigest: artifact.Digest{1}, AssignmentID: "22222222-2222-2222-2222-222222222222"}
	p := Projection{Target: target, Revision: revision, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []CurrentAssignment{{Audience: a, ObservedAt: now, FreshUntil: now.Add(20 * time.Second)}}}
	e := Retained{ArtifactID: "33333333-3333-3333-3333-333333333333", Target: target, DataClass: "metadata", ExpiresAt: now.Add(time.Hour), Audience: []artifact.AudienceAssignment{a}}
	return i, p, e, now
}

func TestEmptyDenySnapshotCannotOutliveFiveSeconds(t *testing.T) {
	i, p, e, now := fixture()
	if r := Evaluate(i, p, DownloadApproved, p.Target, &e, now.Add(6*time.Second)); r.Eligible {
		t.Fatal("an empty deny snapshot older than five seconds authorized disclosure")
	}
}

// ADR-200 revision (2026-10-23): the accepted permission stream observation,
// including its complete deny snapshot and deny rows, is current for 30
// seconds after its own observation.
func TestPermissionObservationThirtySecondLifetime(t *testing.T) {
	for _, test := range []struct {
		name          string
		age, lifetime time.Duration
		want          bool
	}{
		{"observed-20s-ago", 20 * time.Second, 30 * time.Second, true},
		{"observed-31s-ago", 31 * time.Second, 30 * time.Second, false},
		{"lifetime-over-30s", 20 * time.Second, 31 * time.Second, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			i, p, e, now := fixture()
			observed := now.Add(-test.age)
			p.DeniesObservedAt, p.DeniesFreshUntil = observed, observed.Add(test.lifetime)
			deny := p.Allows[0]
			deny.Audience.SubjectID, deny.Audience.AssignmentID = "unrelated-team", "44444444-4444-4444-4444-444444444444"
			deny.ObservedAt, deny.FreshUntil = observed, observed.Add(test.lifetime)
			p.Denies = []CurrentAssignment{deny}
			if r := Evaluate(i, p, ReadApproved, p.Target, &e, now); r.Eligible != test.want {
				t.Fatalf("eligible=%t want=%t reason=%s", r.Eligible, test.want, r.Reason)
			}
		})
	}
}

func TestDenySnapshotDeadlineIsIndependentAndNotRenewable(t *testing.T) {
	for _, change := range []string{"missing", "too long", "stale", "future", "old row"} {
		t.Run(change, func(t *testing.T) {
			i, p, e, now := fixture()
			switch change {
			case "missing":
				p.DeniesObservedAt = time.Time{}
			case "too long":
				p.DeniesFreshUntil = now.Add(PermissionObservationInterval + time.Second)
			case "stale":
				p.DeniesObservedAt = now.Add(-5 * time.Second)
				p.DeniesFreshUntil = now
			case "future":
				p.DeniesObservedAt = now.Add(time.Second)
			case "old row":
				row := p.Allows[0]
				row.Audience.SubjectID = "unrelated-team"
				row.FreshUntil = row.ObservedAt.Add(PermissionObservationInterval + time.Second)
				p.Denies = []CurrentAssignment{row}
			}
			if r := Evaluate(i, p, ReadApproved, p.Target, &e, now); r.Eligible || r.Reason != "PermissionUnavailable" {
				t.Fatal("invalid deny freshness accepted")
			}
		})
	}
	i, p, e, now := fixture()
	row := p.Allows[0]
	row.FreshUntil = p.DeniesFreshUntil
	row.Audience.Role = "evidence-reader"
	p.Denies = []CurrentAssignment{row}
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, now); r.Reason != "ExplicitDeny" {
		t.Fatal("current explicit deny did not win")
	}
}

func TestOrdinaryDeveloperCanCollectReadAndDownload(t *testing.T) {
	for _, op := range []Operation{CollectContext, ReadApproved, DownloadApproved} {
		t.Run(string(op), func(t *testing.T) {
			i, p, e, now := fixture()
			var retained *Retained
			if op != CollectContext {
				retained = &e
			}
			r := Evaluate(i, p, op, p.Target, retained, now)
			if !r.Eligible || !r.ValidUntil.Equal(p.DeniesFreshUntil) {
				t.Fatalf("ordinary workflow denied: %s", r.Reason)
			}
		})
	}
	for _, role := range []string{"evidence-reader", "evidence-owner", "action-approver"} {
		t.Run(role, func(t *testing.T) {
			i, p, e, now := fixture()
			p.Allows[0].Audience.Role = role
			e.Audience[0].Role = role
			if r := Evaluate(i, p, CollectContext, p.Target, nil, now); r.Eligible {
				t.Fatal("nonmaintainer collected")
			}
			r := Evaluate(i, p, DownloadApproved, p.Target, &e, now)
			if r.Eligible != (role != "action-approver") {
				t.Fatal("role read semantics changed")
			}
		})
	}
}

func TestOwnershipAndDenyBoundaries(t *testing.T) {
	tests := map[string]func(*identity.Identity, *Projection, *Retained, time.Time){
		"unknown denies": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { p.DeniesComplete = false },
		"explicit deny beats allow": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			p.Denies = append(p.Denies, p.Allows[0])
			p.Denies[0].Audience.Role = "evidence-reader"
		},
		"stale deny beats independent allow": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			p.Denies = append(p.Denies, p.Allows[0])
			p.Denies[0].FreshUntil = n
		},
		"stale source": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { p.Allows[0].FreshUntil = n },
		"future source": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			p.Allows[0].ObservedAt = n.Add(time.Second)
		},
		"stale identity":   func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { i.ValidUntil = n },
		"stale config":     func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { p.FreshUntil = n },
		"expired artifact": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { e.ExpiresAt = n },
		"recreated namespace": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			e.Target.NamespaceUID = "new-namespace"
		},
		"other cluster": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			e.Target.ClusterID = "44444444-4444-4444-4444-444444444444"
		},
		"replacement pod": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { e.Target.PodUID = "new-pod" },
		"same group under other issuer": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			i.Principal.Issuer = "https://other.example.invalid"
		},
		"new owner cannot read old evidence": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			i.Groups = []string{"team-b"}
			p.Allows[0].Audience.SubjectID = "team-b"
		},
		"A B A reassignment": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			p.Allows[0].Audience.AssignmentID = "44444444-4444-4444-4444-444444444444"
		},
		"source replacement": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			p.Allows[0].Audience.BasisUID = "new-source"
		},
		"changed source scope": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			p.Allows[0].Audience.BasisDigest = artifact.Digest{2}
		},
		"removed member": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { i.Groups = nil },
		"download scope required": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) {
			i.Scopes = []string{"evidence:read"}
		},
		"raw needs its own path": func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { e.DataClass = "raw" },
		"unknown class":          func(i *identity.Identity, p *Projection, e *Retained, n time.Time) { e.DataClass = "safe" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			i, p, e, n := fixture()
			mutate(&i, &p, &e, n)
			r := Evaluate(i, p, DownloadApproved, p.Target, &e, n)
			if r.Eligible {
				t.Fatal("unsafe eligibility")
			}
			if len(r.ContributingAssignments) > 0 || r.Principal.Subject != "" {
				t.Fatal("failure leaks provenance")
			}
		})
	}
}

func TestFreshnessAndAudienceBounds(t *testing.T) {
	i, p, e, n := fixture()
	stale := p.Allows[0]
	stale.Audience.AssignmentID = "44444444-4444-4444-4444-444444444444"
	stale.FreshUntil = n
	p.Allows = append(p.Allows, stale)
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, n); !r.Eligible {
		t.Fatal("unavailable unrelated allow blocked independent assignment")
	}
	i.Groups = append(i.Groups, "new-team-member-group") // existing stable team still matches
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, n); !r.Eligible {
		t.Fatal("legitimate membership update denied")
	}
	for index := len(p.Allows); index < 34; index++ {
		a := p.Allows[0]
		a.Audience.AssignmentID = fmt.Sprintf("%08x-1111-1111-1111-111111111111", index)
		p.Allows = append(p.Allows, a)
	}
	if r := Evaluate(i, p, CollectContext, p.Target, nil, n); r.Eligible || r.Reason != "AudienceOverflow" {
		t.Fatal("audience overflow silently omitted")
	}
	// Current configuration may have grown since a small retained audience was
	// recorded. It must not make reading that original artifact impossible.
	if r := ScopeEligibility(i, p, ReadApproved, p.Target, n); !r.Eligible {
		t.Fatal("current assignment growth blocked old evidence before lookup")
	}
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, n); !r.Eligible || len(r.ContributingAssignments) != 1 {
		t.Fatal("retained audience was not narrowed independently")
	}
	if r := Evaluate(i, p, Operation("dump"), p.Target, nil, n); r.Eligible {
		t.Fatal("unknown intrusive action accepted")
	}
}

func TestRetainedMultipleTeamsAndNewMembers(t *testing.T) {
	i, p, e, n := fixture()
	other := p.Allows[0]
	other.Audience.AssignmentID = "44444444-4444-4444-4444-444444444444"
	other.Audience.SubjectID = "team-b"
	other.Audience.Role = "evidence-owner"
	p.Allows = append(p.Allows, other)
	e.Audience = append(e.Audience, other.Audience)
	i.Principal.Subject = "another-developer"
	i.Groups = []string{"team-b"}
	if r := Evaluate(i, p, DownloadApproved, p.Target, &e, n); !r.Eligible {
		t.Fatal("second retained owner team cannot read")
	}
	i.Principal.Subject = "new-team-member"
	i.Groups = []string{"team-a"}
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, n); !r.Eligible {
		t.Fatal("current member of original team denied")
	}
	i.Principal.Subject = "original-creator"
	i.Groups = nil
	if r := Evaluate(i, p, ReadApproved, p.Target, &e, n); r.Eligible {
		t.Fatal("creator identity manufactured entitlement")
	}
}
