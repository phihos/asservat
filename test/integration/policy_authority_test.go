package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL, role separation and encrypted S3 receipts. Protected Kubernetes
// source/signature/compiler inputs and KMS custody are explicitly synthetic.
func TestPermissionAuthorityPoliciesWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run make custody-integration")
	}
	var f struct{ Postgres, S3 string }
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(data)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	poolFor := func(role, password string) *pgxpool.Pool {
		pc, err := pgxpool.ParseConfig("postgres://" + role + ":" + password + "@" + address + "/custody_test?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		pc.ConnConfig.TLSConfig = tlsConfig
		pc.ConnConfig.Fallbacks = nil
		pc.MaxConns = 16
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	configPool := poolFor("authority_runtime", "synthetic-authority")
	sourcePool := poolFor("policy_source_runtime", "synthetic-policy-source")
	acceptPool := poolFor("policy_accept_runtime", "synthetic-policy-accept")
	auditPool := poolFor("policy_audit_runtime", "synthetic-policy-audit")
	readPool := poolFor("policy_read_runtime", "synthetic-policy-read")
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	bucket := "policy-audit"
	if _, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	keys := authorityTestKeys{aead}
	objects := &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}
	policyObjects := &objectstore.PolicyAcceptanceObjects{Store: store, Seal: keys, Open: keys}
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	type setup struct {
		p                           *postgres.Permissions
		source, accept, audit, read *postgres.Policies
		current                     *postgres.AutomationAuthorities
		batch                       cfg.PermissionBatch
		observation                 capture.PolicySource
		input                       capture.PolicyAdmission
	}
	flushPermissions := func(t *testing.T, p *postgres.Permissions) {
		t.Helper()
		if err := (auditapp.AuthorityPublisher{Ledger: p, Objects: objects}).PublishAuthority(ctx); err != nil {
			t.Fatal(err)
		}
	}
	newSetup := func(t *testing.T) setup {
		t.Helper()
		root, epoch, installation, cluster, ns, workload, policy := custodyID(), custodyID(), custodyID(), custodyID(), custodyID(), custodyID(), custodyID()
		now := clock()
		p, err := postgres.NewPermissions(ctx, configPool, root)
		if err != nil {
			t.Fatal(err)
		}
		trust := artifact.Digest{1}
		if _, err = p.BeginPermissions(ctx, root, epoch, trust); err != nil {
			t.Fatal(err)
		}
		basis := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "v1", SpecDigest: artifact.Digest{2}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: "app", UID: ns}}, Effect: "Allow", Subjects: []cfg.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-a"}}, Roles: []string{"workload-maintainer"}, Automation: &authorization.AutomationEnvelope{AllowedActions: []string{"logs", "packetCapture"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 1000, MaxObservedBytes: 2000}}
		basis.ScopeDigest = configapp.PermissionScopeDigest(basis)
		review := cfg.BootstrapReview{Resource: cfg.Resource{ClusterID: cluster, Namespace: "asservat", NamespaceUID: "control", Kind: "ConfigMap", UID: custodyID(), ResourceVersion: "v1", SpecDigest: artifact.Digest{9}}, Reviewer: "synthetic-administrator", BindingsDigest: artifact.Digest{8}, ReviewedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		batch := cfg.PermissionBatch{RootID: root, Epoch: epoch, RequestID: custodyID(), TrustDigest: trust, InputDigest: artifact.Digest{3}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Bases: []cfg.PermissionBasis{basis}, Initial: &cfg.PermissionInitialization{ClusterID: cluster, Control: cfg.NamespaceRef{Name: "asservat", UID: "control"}, BindingCount: 1, BindingsDigest: review.BindingsDigest, Review: &review}}
		accepted, err := p.AcceptPermissions(ctx, batch)
		if err != nil {
			t.Fatal(err)
		}
		batch.ExpectedSequence = accepted.Sequence
		flushPermissions(t, p)
		target := authorization.Target{ClusterID: cluster, NamespaceUID: ns, WorkloadUID: workload, PodUID: custodyID()}
		projection, err := p.Permissions(ctx, target)
		if err != nil || len(projection.Allows) != 1 {
			t.Fatalf("permission setup: %+v %v", projection, err)
		}
		actor := identity.Principal{Issuer: basis.Subjects[0].Issuer, Subject: "developer", ClientID: "console", Kind: identity.Human}
		authority := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: policy, Creator: actor, Executor: authorization.PolicyPrincipal(installation, policy), ScopeDigest: artifact.Digest{10}, ClusterID: cluster, NamespaceUID: ns, WorkloadUID: workload, Delegation: identity.Revision{UID: basis.Resource.UID, Generation: 1, Digest: basis.Resource.SpecDigest}, Owners: []artifact.AudienceAssignment{projection.Allows[0].Audience}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1000, MaxObservedBytes: 2000}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
		rproof := artifact.RecoveryProof{InstallationID: installation, IssuerEpoch: custodyID(), Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{4}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		if _, err = admin.Exec(ctx, `INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'recovery',1,$3,false,false,$4,$5)`, installation, rproof.IssuerEpoch, rproof.Revision.Digest[:], now, now.Add(30*time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := seedSyntheticFleetObservation(ctx, admin, installation); err != nil {
			t.Fatal(err)
		}
		factory := func(pool *pgxpool.Pool) *postgres.Policies {
			r, err := postgres.NewPolicies(ctx, pool, root, installation)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		s := setup{p: p, source: factory(sourcePool), accept: factory(acceptPool), audit: factory(auditPool), read: factory(readPool), batch: batch}
		s.current, err = postgres.NewAutomationAuthorities(ctx, readPool, root, installation)
		if err != nil {
			t.Fatal(err)
		}
		s.observation = capture.PolicySource{InstallationID: installation, ClusterID: cluster, NamespaceUID: ns, Name: "packet-debug", Revision: identity.Revision{UID: policy, Generation: 1, Digest: artifact.Digest{5}}, ResourceVersion: "policy-v1", CollectionDigest: artifact.Digest{6}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		if err = s.source.ObservePolicy(ctx, s.observation); err != nil {
			t.Fatal(err)
		}
		s.input = capture.PolicyAdmission{RootID: root, Recovery: rproof, Target: target, Authority: authority, Author: identity.Identity{Principal: actor, Scopes: []string{"evidence:capture"}, Groups: []string{"team-a"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{7}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}, Submission: capture.VerifiedPolicySubmission{Nonce: custodyID(), Actor: actor, Source: s.observation.Revision, ClusterID: cluster, NamespaceUID: ns, Name: s.observation.Name, ScopeDigest: authority.ScopeDigest, EnvelopeDigest: artifact.Digest{8}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}}
		s.input.Verification = syntheticSubmissionCheck(s.input, now)
		return s
	}
	accept := func(t *testing.T, s setup) capture.AcceptedPolicy {
		t.Helper()
		r, err := s.accept.AcceptPolicy(ctx, s.input)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	flush := func(t *testing.T, s setup) {
		t.Helper()
		if err := (auditapp.PolicyAcceptancePublisher{Ledger: s.audit, Objects: policyObjects}).PublishPolicyAcceptances(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eligible := func(s setup) authorization.PolicyEligibility {
		return (authapp.AutomationEvaluator{Accepted: s.read, Current: s.current, Now: time.Now}).Eligibility(ctx, authorization.PolicyUse{PolicyUID: s.input.Authority.PolicyUID, ScopeDigest: s.input.Authority.ScopeDigest, Target: s.input.Target, Purpose: authorization.PolicyIncident})
	}
	observe := func(t *testing.T, s *setup) {
		t.Helper()
		s.observation.ObservedAt = clock()
		s.observation.FreshUntil = s.observation.ObservedAt.Add(5 * time.Second)
		s.observation.ResourceVersion = custodyID()
		if err := s.source.ObservePolicy(ctx, s.observation); err != nil {
			t.Fatal(err)
		}
	}
	rebind := func(t *testing.T, s *setup) {
		t.Helper()
		s.batch.RequestID = custodyID()
		s.batch.ObservedAt = clock()
		s.batch.FreshUntil = s.batch.ObservedAt.Add(5 * time.Second)
		s.batch.InputDigest[0]++
		b := &s.batch.Bases[0]
		b.Resource.Generation++
		b.Resource.SpecDigest[0]++
		b.Resource.ResourceVersion = custodyID()
		b.Continuous = true
		r, err := s.p.AcceptPermissions(ctx, s.batch)
		if err != nil {
			t.Fatal(err)
		}
		s.batch.ExpectedSequence = r.Sequence
	}

	t.Run("audit-gated-durable-and-no-personal-session-dependency", func(t *testing.T) {
		s := newSetup(t)
		r := accept(t, s)
		if r.Replay || !r.Record.Valid() {
			t.Fatal("invalid receipt")
		}
		if eligible(s).Eligible {
			t.Fatal("unaudited policy became eligible")
		}
		flush(t, s)
		got := eligible(s)
		if !got.Eligible || got.ValidUntil.After(s.observation.FreshUntil) {
			t.Fatalf("audited team authority rejected: %+v", got)
		}
		s.input.Author.Groups = nil
		s.input.Author.ValidUntil = clock().Add(-time.Second)
		if !eligible(s).Eligible {
			t.Fatal("creator departure stopped team authority")
		}
		restarted, err := postgres.NewPolicies(ctx, readPool, s.input.RootID, s.input.Authority.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := restarted.AcceptedPolicyAuthority(ctx, s.input.Authority.PolicyUID)
		if err != nil || snapshot.Authority.ScopeDigest != s.input.Authority.ScopeDigest {
			t.Fatal("restart lost acceptance", err)
		}
		receipt, err := policyObjects.WritePolicyAcceptance(ctx, r.Record)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.audit.AcknowledgePolicyAcceptance(ctx, r.Record, receipt); err != nil {
			t.Fatal("exact audit retry", err)
		}
		changed := receipt
		changed.SHA256[0]++
		if err = s.audit.AcknowledgePolicyAcceptance(ctx, r.Record, changed); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("changed receipt accepted", err)
		}
		tampered := r.Record
		tampered.Authority.ScopeDigest[0]++
		tampered.Submission.ScopeDigest = tampered.Authority.ScopeDigest
		if _, err = policyObjects.WritePolicyAcceptance(ctx, tampered); err == nil {
			t.Fatal("existing audit replaced with different accepted scope")
		}
		object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &receipt.Key})
		if err != nil {
			t.Fatal(err)
		}
		defer object.Body.Close()
		var envelope map[string]any
		if json.NewDecoder(object.Body).Decode(&envelope) != nil {
			t.Fatal("encrypted audit unreadable")
		}
		encoded, _ := json.Marshal(envelope)
		if bytes.Contains(encoded, []byte("developer")) || bytes.Contains(encoded, []byte("team-a")) {
			t.Fatal("plaintext identity in object audit")
		}
	})
	for _, kind := range []string{"automation-envelope", "policy-acceptance"} {
		for _, version := range []string{"", "null"} {
			label := version
			if label == "" {
				label = "empty"
			}
			t.Run("retained-"+kind+"-"+label, func(t *testing.T) {
				s := newSetup(t)
				// Give the current automation envelope its own acknowledgement:
				// the original ordinary assignment and initial/reset receipts stay
				// valid, so their checks cannot mask a missing envelope check.
				rebind(t, &s)
				s.input.Authority.Delegation = identity.Revision{UID: s.batch.Bases[0].Resource.UID, Generation: s.batch.Bases[0].Resource.Generation, Digest: s.batch.Bases[0].Resource.SpecDigest}
				flushPermissions(t, s.p)
				s.input.Verification = syntheticSubmissionCheck(s.input, clock())
				accepted := accept(t, s)
				flush(t, s)
				baseline := eligible(s)
				if !baseline.Eligible {
					t.Fatal("original versioned policy unavailable", baseline)
				}
				deny := func() {
					if kind == "automation-envelope" {
						ordinary, err := s.p.Permissions(ctx, s.input.Target)
						if err != nil || len(ordinary.Allows) != 1 || !ordinary.DeniesComplete {
							t.Fatal("old envelope receipt affected separate ordinary assignment", err)
						}
						if _, err := s.current.PolicyAutomationAuthority(ctx, s.input.Authority, s.input.Target); err == nil {
							t.Fatal("historical automation envelope became current")
						}
					} else if _, err := s.read.AcceptedPolicyAuthority(ctx, s.input.Authority.PolicyUID); err == nil {
						t.Fatal("historical policy acceptance became current")
					}
					if eligible(s).Eligible {
						t.Fatal("historical audit authorized policy execution")
					}
					// Nonce replay is historical provenance, not re-acceptance.
					replayed, err := s.accept.AcceptPolicy(ctx, s.input)
					if err != nil || !replayed.Replay || replayed.Record.ID != accepted.Record.ID || !replayed.Record.AcceptedAt.Equal(accepted.Record.AcceptedAt) {
						t.Fatal("exact historical nonce replay changed", err)
					}
					if eligible(s).Eligible {
						t.Fatal("historical nonce replay repaired audit authority")
					}
					if !clock().Before(baseline.ValidUntil) {
						t.Fatal("historical policy denial crossed original authority deadline")
					}
				}
				if kind == "automation-envelope" {
					var event string
					if err := admin.QueryRow(ctx, "SELECT automation_audit_id FROM permission_basis WHERE stream_id=$1 AND uid=$2", s.input.RootID, s.batch.Bases[0].Resource.UID).Scan(&event); err != nil {
						t.Fatal(err)
					}
					withHistoricalAuthorityVersion(t, ctx, admin, s.input.RootID, event, version, deny)
				} else {
					withHistoricalAuditReceipt(t, ctx, admin,
						"SELECT receipt_json FROM policy_acceptance WHERE root_id=$1 AND id=$2",
						"UPDATE policy_acceptance SET receipt_json=$3 WHERE root_id=$1 AND id=$2",
						[]any{s.input.RootID, accepted.Record.ID}, func(r *audit.Receipt) { r.Version = version }, deny)
				}
				if restored := eligible(s); !restored.Eligible {
					t.Fatal("exact original policy history did not restore baseline", restored)
				}
			})
		}
	}
	t.Run("concurrent-nonce-replay-is-one-immutable-acceptance", func(t *testing.T) {
		s := newSetup(t)
		var wg sync.WaitGroup
		results := make(chan capture.AcceptedPolicy, 12)
		failures := make(chan error, 12)
		for range 12 {
			wg.Add(1)
			go func() { defer wg.Done(); r, e := s.accept.AcceptPolicy(ctx, s.input); results <- r; failures <- e }()
		}
		wg.Wait()
		close(results)
		close(failures)
		for e := range failures {
			if e != nil {
				t.Fatal(e)
			}
		}
		var first capture.PolicyAcceptance
		fresh := 0
		for r := range results {
			if first.ID == "" {
				first = r.Record
			}
			if r.Record.ID != first.ID || !r.Record.Authority.NotAfter.Equal(first.Authority.NotAfter) {
				t.Fatal("replay changed authority")
			}
			if !r.Replay {
				fresh++
			}
		}
		if fresh != 1 {
			t.Fatal("multiple acceptances", fresh)
		}
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM policy_acceptance WHERE root_id=$1", s.input.RootID).Scan(&count); err != nil || count != 1 {
			t.Fatal("duplicate nonce rows", count, err)
		}
		conflict := s.input
		conflict.Authority.Limits.MaxBytes--
		if _, e := s.accept.AcceptPolicy(ctx, conflict); !errors.Is(e, capture.ErrConflict) {
			t.Fatal("nonce reused for changed scope", e)
		}
		conflict = s.input
		conflict.Submission.Nonce = custodyID()
		conflict.Submission.ReplacesID = first.ID
		conflict.Verification = syntheticSubmissionCheck(conflict, clock())
		if _, e := s.accept.AcceptPolicy(ctx, conflict); !errors.Is(e, capture.ErrConflict) {
			t.Fatal("new nonce reset same scope", e)
		}
	})
	t.Run("binding-revision-and-audit-are-independent-of-historical-owner", func(t *testing.T) {
		s := newSetup(t)
		accept(t, s)
		flush(t, s)
		old := s.input.Authority.Owners[0]
		rebind(t, &s)
		if eligible(s).Eligible {
			t.Fatal("old policy inherited new delegation")
		}
		s.input.Authority.Delegation = identity.Revision{UID: s.batch.Bases[0].Resource.UID, Generation: s.batch.Bases[0].Resource.Generation, Digest: s.batch.Bases[0].Resource.SpecDigest}
		if _, err := s.current.PolicyAutomationAuthority(ctx, s.input.Authority, s.input.Target); err == nil {
			t.Fatal("unaudited current envelope accepted")
		}
		flushPermissions(t, s.p)
		current, err := s.current.PolicyAutomationAuthority(ctx, s.input.Authority, s.input.Target)
		if err != nil {
			t.Fatal(err)
		}
		if len(current.Permissions.Allows) != 1 || current.Permissions.Allows[0].Audience != old {
			t.Fatal("ordinary historical access was retired")
		}
		use := authorization.PolicyUse{PolicyUID: s.input.Authority.PolicyUID, ScopeDigest: s.input.Authority.ScopeDigest, Target: s.input.Target, Purpose: authorization.PolicyIncident}
		if !authorization.ValidatePolicyAcceptance(s.input.Author, s.input.Authority, current, use, clock()).Eligible {
			t.Fatal("new policy cannot use unchanged historical assignment")
		}
		// Simulated storage corruption cannot borrow the acknowledged source audit.
		if _, err = admin.Exec(ctx, `UPDATE permission_basis SET automation_json=jsonb_set(automation_json,'{MaxBytes}','999') WHERE stream_id=$1`, s.input.RootID); err != nil {
			t.Fatal(err)
		}
		if _, err = s.current.PolicyAutomationAuthority(ctx, s.input.Authority, s.input.Target); err == nil {
			t.Fatal("changed unaudited envelope inherited acknowledgement")
		}
	})
	t.Run("pause-resume-does-not-create-new-authority", func(t *testing.T) {
		s := newSetup(t)
		r := accept(t, s)
		flush(t, s)
		s.observation.Revision.Generation++
		s.observation.Revision.Digest[0]++
		s.observation.Suspended = true
		observe(t, &s)
		if eligible(s).Eligible {
			t.Fatal("paused policy eligible")
		}
		s.observation.Revision.Generation++
		s.observation.Revision.Digest[0]++
		s.observation.Suspended = false
		observe(t, &s)
		if !eligible(s).Eligible {
			t.Fatal("resume demanded new acceptance")
		}
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM policy_acceptance WHERE root_id=$1", s.input.RootID).Scan(&count); err != nil || count != 1 {
			t.Fatal("resume reset scope", err)
		}
		got, err := s.read.AcceptedPolicyAuthority(ctx, s.input.Authority.PolicyUID)
		if err != nil || !got.Authority.NotAfter.Equal(r.Record.Authority.NotAfter) {
			t.Fatal("resume extended expiry", err)
		}
		s.observation.Revision.Generation++
		s.observation.Revision.Digest[0]++
		s.observation.CollectionDigest[0]++
		observe(t, &s)
		if eligible(s).Eligible {
			t.Fatal("changed collection intent reused approval")
		}
		s.observation.Revision.Generation++
		s.observation.Revision.Digest[0]++
		s.observation.CollectionDigest[0]--
		observe(t, &s)
		if eligible(s).Eligible {
			t.Fatal("A-B-A edit revived old intent")
		}
	})
	t.Run("missed-policy-generations-cannot-assert-intent-continuity", func(t *testing.T) {
		s := newSetup(t)
		accept(t, s)
		flush(t, s)
		// A relist may return the original collection digest after an unobserved
		// A -> B -> A. Its jumped generation must invalidate the old acceptance.
		s.observation.Revision.Generation += 2
		s.observation.Revision.Digest[0]++
		observe(t, &s)
		if eligible(s).Eligible {
			t.Fatal("generation gap revived original collection intent")
		}
	})
	t.Run("current-team-editor-keeps-creator-and-pins-replacement", func(t *testing.T) {
		s := newSetup(t)
		first := accept(t, s)
		flush(t, s)
		s.input.Author.Principal.Subject = "second-developer"
		s.input.Submission.Actor = s.input.Author.Principal
		s.input.Submission.Nonce = custodyID()
		s.input.Submission.EnvelopeDigest[0]++
		s.input.Authority.ScopeDigest[0]++
		s.input.Submission.ScopeDigest = s.input.Authority.ScopeDigest
		s.input.Verification = syntheticSubmissionCheck(s.input, clock())
		if _, e := s.accept.AcceptPolicy(ctx, s.input); !errors.Is(e, capture.ErrConflict) {
			t.Fatal("unbound replacement accepted", e)
		}
		s.input.Submission.ReplacesID = first.Record.ID
		s.input.Verification = syntheticSubmissionCheck(s.input, clock())
		wrong := s.input
		wrong.Authority.Creator = wrong.Author.Principal
		if _, e := s.accept.AcceptPolicy(ctx, wrong); e == nil {
			t.Fatal("creator rewritten")
		}
		second := accept(t, s)
		if second.Record.Authority.Creator != first.Record.Authority.Creator || second.Record.Submitter == first.Record.Submitter {
			t.Fatal("editor and creator conflated")
		}
		if eligible(s).Eligible {
			t.Fatal("replacement inherited previous audit")
		}
		flush(t, s)
		if !eligible(s).Eligible {
			t.Fatal("audited edited authority rejected")
		}
	})
	for _, name := range []string{"deleted", "expired-source", "recovery-blocked", "issuer-epoch", "scope-tamper", "departed-at-acceptance", "actor-substitution", "removed-envelope", "team-deny"} {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			if name == "departed-at-acceptance" {
				s.input.Author.Groups = nil
				if _, e := s.accept.AcceptPolicy(ctx, s.input); e == nil {
					t.Fatal("departed author accepted")
				}
				return
			}
			if name == "actor-substitution" {
				s.input.Submission.Actor.Subject = "someone-else"
				if _, e := s.accept.AcceptPolicy(ctx, s.input); e == nil {
					t.Fatal("unsigned actor accepted")
				}
				return
			}
			accept(t, s)
			flush(t, s)
			switch name {
			case "deleted":
				s.observation.Deleted = true
				observe(t, &s)
				s.observation.Deleted = false
				s.observation.ObservedAt = clock()
				s.observation.FreshUntil = s.observation.ObservedAt.Add(5 * time.Second)
				if err = s.source.ObservePolicy(ctx, s.observation); err == nil {
					t.Fatal("deleted UID revived")
				}
			case "expired-source":
				// One exact instant: two clock_timestamp() calls can differ by
				// a microsecond and violate the intentionally strict 5s bound.
				observed := clock().Add(-6 * time.Second)
				if _, err = admin.Exec(ctx, "UPDATE policy_source SET observed_at=$2,fresh_until=$3 WHERE root_id=$1", s.input.RootID, observed, observed.Add(5*time.Second)); err != nil {
					t.Fatal(err)
				}
			case "recovery-blocked":
				if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", s.input.Authority.InstallationID); err != nil {
					t.Fatal(err)
				}
			case "issuer-epoch":
				if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET issuer_epoch=$2 WHERE installation_id=$1", s.input.Authority.InstallationID, custodyID()); err != nil {
					t.Fatal(err)
				}
			case "scope-tamper":
				if _, err = admin.Exec(ctx, `UPDATE policy_acceptance SET record=jsonb_set(record,'{Authority,Limits,MaxBytes}','999') WHERE root_id=$1`, s.input.RootID); err != nil {
					t.Fatal(err)
				}
			case "removed-envelope":
				s.batch.Bases[0].Automation = nil
				rebind(t, &s)
			case "team-deny":
				deny := s.batch.Bases[0]
				deny.Automation = nil
				deny.Resource.UID = custodyID()
				deny.Effect = "Deny"
				deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
				s.batch.Bases = append(s.batch.Bases, deny)
				rebind(t, &s)
			}
			if eligible(s).Eligible {
				t.Fatal("unavailable/revoked policy eligible")
			}
		})
	}
	for _, expiry := range []string{"envelope", "signature-trust"} {
		t.Run("expiry-after-lock-wait-rolls-back-all-acceptance/"+expiry, func(t *testing.T) {
			s := newSetup(t)
			if expiry == "envelope" {
				s.input.Submission.ExpiresAt = clock().Add(150 * time.Millisecond)
			}
			s.input.Verification = syntheticSubmissionCheck(s.input, clock())
			s.input.Verification.ValidUntil = clock().Add(150 * time.Millisecond)
			if expiry == "envelope" {
				s.input.Verification.ValidUntil = s.input.Submission.ExpiresAt
			}
			tx, e := admin.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			if _, e = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.input.RootID); e != nil {
				t.Fatal(e)
			}
			result := make(chan error, 1)
			go func() { _, e := s.accept.AcceptPolicy(ctx, s.input); result <- e }()
			time.Sleep(250 * time.Millisecond)
			if e = tx.Commit(ctx); e != nil {
				t.Fatal(e)
			}
			if e = <-result; e == nil {
				t.Fatal("expired submission accepted after waiting")
			}
			var count int
			if e = admin.QueryRow(ctx, "SELECT count(*) FROM policy_acceptance WHERE root_id=$1", s.input.RootID).Scan(&count); e != nil || count != 0 {
				t.Fatal("failed acceptance persisted", e)
			}
			var creator []byte
			if e = admin.QueryRow(ctx, "SELECT creator_json FROM policy_source WHERE root_id=$1", s.input.RootID).Scan(&creator); e != nil || len(creator) != 0 {
				t.Fatal("failed acceptance pinned creator", e)
			}
		})
	}

	t.Run("signed-submission-to-atomic-acceptance", func(t *testing.T) {
		s := newSetup(t)
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		x := s.input.Submission
		expected := capture.PolicySubmissionIntent{RootID: s.input.RootID, InstallationID: s.input.Authority.InstallationID, IssuerEpoch: s.input.Recovery.IssuerEpoch, ReplacesID: x.ReplacesID, Nonce: x.Nonce, Actor: x.Actor, Source: x.Source, ClusterID: x.ClusterID, NamespaceUID: x.NamespaceUID, Name: x.Name, ScopeDigest: x.ScopeDigest, IssuedAt: x.IssuedAt, ExpiresAt: x.ExpiresAt}
		trust := &submissionFixtureTrust{value: capture.SubmissionTrust{RootID: expected.RootID, InstallationID: expected.InstallationID, IssuerEpoch: expected.IssuerEpoch, Revision: identity.Revision{UID: "synthetic-signature-trust", Generation: 1, Digest: artifact.Digest{92}}, Keys: []capture.SubmissionKey{{ID: "test-key", PublicKey: pub, NotBefore: clock().Add(-time.Minute), NotAfter: clock().Add(time.Hour)}}}}
		protocol, e := jose.NewPolicySubmissions(expected.RootID, expected.InstallationID, expected.IssuerEpoch, "test-key", trust, func(context.Context) crypto.Signer { return key }, clock)
		if e != nil {
			t.Fatal(e)
		}
		signed, e := protocol.SignPolicySubmission(ctx, expected)
		if e != nil {
			t.Fatal(e)
		}
		service := captureapp.SignedPolicyAcceptor{Verifier: protocol, Store: s.accept, Now: clock}
		first, e := service.AcceptPolicySubmission(ctx, signed, expected, s.input)
		if e != nil || first.Replay || first.Record.Submitter != expected.Actor || first.Record.Submission.EnvelopeDigest == x.EnvelopeDigest {
			t.Fatal("verified submission failed admission", e)
		}
		replay, e := service.AcceptPolicySubmission(ctx, signed, expected, s.input)
		if e != nil || !replay.Replay || replay.Record.ID != first.Record.ID || !replay.Record.AcceptedAt.Equal(first.Record.AcceptedAt) {
			t.Fatal("signature verification reset acceptance", e)
		}
		bad := expected
		bad.ScopeDigest[0]++
		if _, e := service.AcceptPolicySubmission(ctx, signed, bad, s.input); e == nil {
			t.Fatal("signed payload substituted scope")
		}
		trust.value.Keys = nil
		if _, e := service.AcceptPolicySubmission(ctx, signed, expected, s.input); e == nil {
			t.Fatal("revoked key reached acceptance service")
		}
	})
	for _, mode := range []string{"missing", "changed-envelope", "wrong-installation", "wrong-epoch"} {
		t.Run("submission-verification/"+mode, func(t *testing.T) {
			s := newSetup(t)
			switch mode {
			case "missing":
				s.input.Verification = capture.SubmissionCheck{}
			case "changed-envelope":
				s.input.Verification.Submission.EnvelopeDigest[0]++
			case "wrong-installation":
				s.input.Verification.InstallationID = custodyID()
			case "wrong-epoch":
				s.input.Verification.IssuerEpoch = custodyID()
			}
			if _, e := s.accept.AcceptPolicy(ctx, s.input); e == nil {
				t.Fatal("unverified submission accepted")
			}
		})
	}
	t.Run("role-boundaries", func(t *testing.T) {
		s := newSetup(t)
		r := accept(t, s)
		checks := []struct {
			pool *pgxpool.Pool
			sql  string
		}{
			{sourcePool, "UPDATE policy_source SET creator_json='{}'"}, {sourcePool, "UPDATE policy_source SET active_id=NULL"},
			{acceptPool, "UPDATE policy_acceptance SET acknowledged_at=clock_timestamp(),receipt_json='{}'"},
			{acceptPool, "UPDATE policy_source SET suspended=false"}, {acceptPool, "UPDATE permission_basis SET automation_json=NULL,automation_audit_id=NULL"},
			{auditPool, "UPDATE policy_acceptance SET record='{}'"}, {auditPool, "UPDATE policy_source SET active_id=NULL"},
			{readPool, "UPDATE policy_source SET fresh_until=clock_timestamp()"}, {readPool, "UPDATE policy_acceptance SET receipt_json='{}'"},
			{sourcePool, "DELETE FROM policy_source"}, {acceptPool, "DELETE FROM policy_acceptance"},
		}
		for _, c := range checks {
			if _, e := c.pool.Exec(ctx, c.sql); e == nil {
				t.Fatal("role escaped", c.sql)
			}
		}
		receipt, e := policyObjects.WritePolicyAcceptance(ctx, r.Record)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.accept.AcknowledgePolicyAcceptance(ctx, r.Record, receipt); e == nil {
			t.Fatal("acceptance role self-acknowledged")
		}
		s.input.Submission.Nonce = custodyID()
		s.input.Submission.ReplacesID = r.Record.ID
		s.input.Authority.ScopeDigest[0]++
		s.input.Submission.ScopeDigest = s.input.Authority.ScopeDigest
		if _, e = s.read.AcceptPolicy(ctx, s.input); e == nil {
			t.Fatal("read role acquired acceptance")
		}
	})
	// ADR-228 trigger ledger through the compiled ordinary hub union grants.
	hubRole := narrowRole(t, ctx, admin, "policy_hub_", "synthetic-policy-hub", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing compiled hub grants")
		}
		return grants
	})
	hubPool := poolFor(hubRole, "synthetic-policy-hub")
	trigger := func(t *testing.T, s setup) *postgres.PolicyTriggers {
		t.Helper()
		r, err := postgres.NewPolicyTriggers(ctx, hubPool, s.input.RootID, s.input.Authority.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	restartPolicy := func(s setup) capture.RestartPolicy {
		return capture.RestartPolicy{ClusterID: s.input.Authority.ClusterID, Namespace: "app", WorkloadKind: "Deployment", WorkloadName: "app", Reasons: []string{"Error", "OOMKilled"}, Interval: 5 * time.Minute, Burst: 2, RetentionSeconds: 3600, ObservedPods: targets.MaxRestartPods}
	}
	observed := func(s setup, pods ...targets.PodRestarts) targets.RestartObservation {
		now := clock()
		a := s.input.Authority
		return targets.RestartObservation{ClusterID: a.ClusterID, Namespace: cfg.NamespaceRef{Name: "app", UID: a.NamespaceUID}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: a.WorkloadUID}, Pods: pods, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	}
	pod := func(uid string, restarts int64) targets.PodRestarts {
		return targets.PodRestarts{Name: "app-" + uid[:8], UID: uid, Restarts: restarts, Reason: "Error", ExitCode: 137}
	}
	// activeTrigger accepts and audits one policy, then refreshes its source.
	activeTrigger := func(t *testing.T) (setup, *postgres.PolicyTriggers) {
		t.Helper()
		s := newSetup(t)
		accept(t, s)
		flush(t, s)
		observe(t, &s)
		return s, trigger(t, s)
	}
	tick := func(t *testing.T, s setup, l *postgres.PolicyTriggers, o targets.RestartObservation) []capture.PolicyOccurrence {
		t.Helper()
		got, err := l.Tick(ctx, capture.PolicyTick{Policy: restartPolicy(s), Authority: s.input.Authority, Observation: o})
		if err != nil {
			t.Fatal("tick", err)
		}
		return got
	}
	suppressed := func(t *testing.T, s setup, reason string) int64 {
		t.Helper()
		var n int64
		if err := admin.QueryRow(ctx, `SELECT coalesce(sum(count),0) FROM policy_suppression WHERE root_id=$1 AND policy_uid=$2 AND reason=$3`, s.input.RootID, s.input.Authority.PolicyUID, reason).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("restart-trigger-baseline-replay-and-concurrent-duplicates", func(t *testing.T) {
		s, l := activeTrigger(t)
		a := custodyID()
		if got := tick(t, s, l, observed(s, pod(a, 1))); len(got) != 0 {
			t.Fatal("first observation fired", got)
		}
		got := tick(t, s, l, observed(s, pod(a, 2)))
		if len(got) != 1 || got[0].PodUID != a || got[0].Restarts != 2 {
			t.Fatal("restart did not fire once", got)
		}
		if again := tick(t, s, l, observed(s, pod(a, 2))); len(again) != 0 {
			t.Fatal("replayed poll fired", again)
		}
		// Concurrent duplicate polls of the next restart: one occurrence.
		var wg sync.WaitGroup
		results := make(chan int, 4)
		o := observed(s, pod(a, 3))
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := l.Tick(ctx, capture.PolicyTick{Policy: restartPolicy(s), Authority: s.input.Authority, Observation: o})
				if err != nil {
					t.Error(err)
				}
				results <- len(r)
			}()
		}
		wg.Wait()
		close(results)
		total := 0
		for n := range results {
			total += n
		}
		var rows, spent int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `SELECT executions_spent FROM policy_acceptance WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID).Scan(&spent); err != nil {
			t.Fatal(err)
		}
		if total != 1 || rows != 2 || spent != 2 {
			t.Fatal("concurrent duplicate polls", total, rows, spent)
		}
		// A Pod missing from one poll keeps its watermark (its next restart is
		// still a candidate); a new Pod is a baseline.
		b := custodyID()
		if got := tick(t, s, l, observed(s, pod(b, 7))); len(got) != 0 {
			t.Fatal("new Pod fired on first sight")
		}
		marks := func() (n, restarts int64) {
			t.Helper()
			if err := admin.QueryRow(ctx, `SELECT count(*), coalesce(max(restarts) FILTER (WHERE pod_uid=$3),-1) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID, a).Scan(&n, &restarts); err != nil {
				t.Fatal(err)
			}
			return
		}
		if n, r := marks(); n != 2 || r != 3 {
			t.Fatal("skipped Pod watermark not kept", n, r)
		}
		// The shared burst is spent, so a's next restart is a cooldown, not a
		// silent re-baseline; a lower count never lowers the watermark.
		cooldown := suppressed(t, s, "cooldown")
		tick(t, s, l, observed(s, pod(a, 4), pod(b, 7)))
		if suppressed(t, s, "cooldown") != cooldown+1 {
			t.Fatal("restart after a skipped poll was not a candidate")
		}
		tick(t, s, l, observed(s, pod(a, 1), pod(b, 7)))
		if _, r := marks(); r != 4 {
			t.Fatal("watermark lowered", r)
		}
		// Rows unseen for ten minutes are pruned.
		if _, err := admin.Exec(ctx, `UPDATE policy_pod_watermark SET last_seen=last_seen-interval '11 minutes' WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3`, s.input.RootID, s.input.Authority.PolicyUID, a); err != nil {
			t.Fatal(err)
		}
		tick(t, s, l, observed(s, pod(b, 7)))
		if n, r := marks(); n != 1 || r != -1 {
			t.Fatal("unseen Pod watermark kept", n, r)
		}
	})
	t.Run("restart-trigger-shared-window-cooldown-and-reopen", func(t *testing.T) {
		s, l := activeTrigger(t)
		a, b, c := custodyID(), custodyID(), custodyID()
		tick(t, s, l, observed(s, pod(a, 1), pod(b, 1), pod(c, 1)))
		// Three Pods restart in one poll, one of them three times: the shared
		// burst of two admits two; the rest are one cooldown and two coalesced.
		got := tick(t, s, l, observed(s, pod(a, 2), pod(b, 2), pod(c, 4)))
		if len(got) != 2 || suppressed(t, s, "cooldown") != 1 || suppressed(t, s, "coalesced") < 2 {
			t.Fatal("burst", len(got), suppressed(t, s, "cooldown"), suppressed(t, s, "coalesced"))
		}
		var rows int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM policy_suppression WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID).Scan(&rows); err != nil || rows != 2 {
			t.Fatal("one suppression row per reason", rows, err)
		}
		if got = tick(t, s, l, observed(s, pod(a, 3), pod(b, 3), pod(c, 5))); len(got) != 0 || suppressed(t, s, "cooldown") != 4 {
			t.Fatal("window did not hold", len(got), suppressed(t, s, "cooldown"))
		}
		// Ten minutes later (shifted in SQL) both budgets have refilled.
		if _, err := admin.Exec(ctx, `UPDATE policy_workload_window SET tat=tat-interval '10 minutes' WHERE root_id=$1`, s.input.RootID); err != nil {
			t.Fatal(err)
		}
		if got = tick(t, s, l, observed(s, pod(a, 4), pod(b, 3), pod(c, 5))); len(got) != 1 || got[0].PodUID != a {
			t.Fatal("window did not reopen", got)
		}
		// A second policy on the same workload shares the workload budget.
		second := s
		second.input.Authority.PolicyUID = custodyID()
		second.input.Authority.Executor = authorization.PolicyPrincipal(s.input.Authority.InstallationID, second.input.Authority.PolicyUID)
		second.input.Authority.ScopeDigest = artifact.Digest{77}
		second.input.Submission.ScopeDigest = second.input.Authority.ScopeDigest
		second.input.Submission.Nonce = custodyID()
		second.observation.Revision.UID = second.input.Authority.PolicyUID
		second.observation.Name = "second-policy"
		second.input.Submission.Source = second.observation.Revision
		second.input.Submission.Name = second.observation.Name
		observe(t, &second)
		second.input.Submission.IssuedAt = clock()
		second.input.Submission.ExpiresAt = second.input.Submission.IssuedAt.Add(30 * time.Second)
		second.input.Recovery.ObservedAt, second.input.Recovery.FreshUntil = clock(), clock().Add(5*time.Second)
		second.input.Author.VerifiedAt, second.input.Author.ValidUntil = clock(), clock().Add(30*time.Second)
		second.input.Verification = syntheticSubmissionCheck(second.input, clock())
		accept(t, second)
		flush(t, second)
		observe(t, &second)
		l2 := trigger(t, second)
		tick(t, second, l2, observed(second, pod(a, 4)))
		if got := tick(t, second, l2, observed(second, pod(a, 5))); len(got) != 1 {
			t.Fatal("second policy within the shared burst", got)
		}
		if got := tick(t, second, l2, observed(second, pod(a, 6))); len(got) != 0 {
			t.Fatal("two policies multiplied the workload budget", got)
		}
		// A storm on this workload leaves another workload's budget untouched.
		other, lo := activeTrigger(t)
		d := custodyID()
		tick(t, other, lo, observed(other, pod(d, 1)))
		if got := tick(t, other, lo, observed(other, pod(d, 2))); len(got) != 1 {
			t.Fatal("independent workload was throttled", got)
		}
	})
	t.Run("restart-trigger-spend-cap-saturation-and-single-link", func(t *testing.T) {
		s, l := activeTrigger(t)
		a := custodyID()
		tick(t, s, l, observed(s, pod(a, 1)))
		max := s.input.Authority.Limits.MaxExecutions
		if _, err := admin.Exec(ctx, `UPDATE policy_acceptance SET executions_spent=$3 WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID, max+1); err == nil {
			t.Fatal("spend above the accepted ceiling stored")
		}
		if _, err := admin.Exec(ctx, `UPDATE policy_acceptance SET executions_spent=$3 WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID, max-1); err != nil {
			t.Fatal(err)
		}
		got := tick(t, s, l, observed(s, pod(a, 2)))
		if len(got) != 1 {
			t.Fatal("last execution not admitted", got)
		}
		if _, err := admin.Exec(ctx, `UPDATE policy_workload_window SET tat=tat-interval '1 hour' WHERE root_id=$1`, s.input.RootID); err != nil {
			t.Fatal(err)
		}
		if more := tick(t, s, l, observed(s, pod(a, 3))); len(more) != 0 || suppressed(t, s, "budget") != 1 {
			t.Fatal("execution ceiling exceeded", more)
		}
		// The occurrence links its one capture once; nothing re-admits it.
		capture := custodyID()
		if err := l.RecordOccurrence(ctx, got[0], capture, ""); err == nil {
			t.Fatal("link to an absent capture accepted")
		}
		if err := l.RecordOccurrence(ctx, got[0], "", "capacity"); err != nil {
			t.Fatal(err)
		}
		if err := l.RecordOccurrence(ctx, got[0], "", "capacity"); err == nil {
			t.Fatal("refused occurrence recorded twice")
		}
		if suppressed(t, s, "capacity") != 1 {
			t.Fatal("capacity refusal not summarized")
		}
		// Saturating content-free counter: one row, bounded count.
		if _, err := admin.Exec(ctx, `UPDATE policy_suppression SET count=2147483646 WHERE root_id=$1 AND policy_uid=$2 AND reason='budget'`, s.input.RootID, s.input.Authority.PolicyUID); err != nil {
			t.Fatal(err)
		}
		tick(t, s, l, observed(s, pod(a, 4)))
		tick(t, s, l, observed(s, pod(a, 5)))
		if suppressed(t, s, "budget") != 2147483647 {
			t.Fatal("suppression count did not saturate", suppressed(t, s, "budget"))
		}
		status, err := l.Status(ctx, s.input.Authority.PolicyUID)
		if err != nil || status.ExecutionsSpent != max || status.Occurrences != 1 || status.WatchedPods != 1 || len(status.Suppressions) < 2 {
			t.Fatal("status", status, err)
		}
	})
	t.Run("restart-trigger-settles-abandoned-occurrences-without-refund", func(t *testing.T) {
		s, l := activeTrigger(t)
		a := custodyID()
		tick(t, s, l, observed(s, pod(a, 1)))
		got := tick(t, s, l, observed(s, pod(a, 2)))
		if len(got) != 1 {
			t.Fatal("restart did not fire", got)
		}
		open := func() (n int64) {
			t.Helper()
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND outcome IS NULL`, s.input.RootID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return
		}
		// A recent open occurrence may still be capturing: it is left alone.
		if err := l.SettleOccurrences(ctx, 2*time.Minute); err != nil || open() != 1 {
			t.Fatal("recent occurrence settled", err)
		}
		if _, err := admin.Exec(ctx, `UPDATE policy_occurrence SET created_at=created_at-interval '3 minutes' WHERE root_id=$1`, s.input.RootID); err != nil {
			t.Fatal(err)
		}
		var spent int64
		if err := l.SettleOccurrences(ctx, 2*time.Minute); err != nil || open() != 0 || suppressed(t, s, "unavailable") != 1 {
			t.Fatal("abandoned occurrence not settled", err)
		}
		if err := admin.QueryRow(ctx, `SELECT executions_spent FROM policy_acceptance WHERE root_id=$1 AND policy_uid=$2`, s.input.RootID, s.input.Authority.PolicyUID).Scan(&spent); err != nil || spent != 1 {
			t.Fatal("settlement refunded spend", spent, err)
		}
		if err := l.RecordOccurrence(ctx, got[0], "", "unavailable"); err == nil {
			t.Fatal("settled occurrence recorded again")
		}
		if err := l.SettleOccurrences(ctx, 2*time.Minute); err != nil || suppressed(t, s, "unavailable") != 1 {
			t.Fatal("settlement repeated", err)
		}
	})
	t.Run("restart-trigger-refuses-stale-suspended-or-replaced-scope", func(t *testing.T) {
		for _, mode := range []string{"suspended", "stale", "other-workload", "other-scope", "unaudited"} {
			t.Run(mode, func(t *testing.T) {
				s, l := activeTrigger(t)
				a := custodyID()
				tick(t, s, l, observed(s, pod(a, 1)))
				o := observed(s, pod(a, 2))
				in := capture.PolicyTick{Policy: restartPolicy(s), Authority: s.input.Authority, Observation: o}
				switch mode {
				case "suspended":
					s.observation.Suspended = true
					s.observation.Revision.Generation++
					observe(t, &s)
				case "stale":
					if _, err := admin.Exec(ctx, `UPDATE policy_source SET observed_at=observed_at-interval '1 minute',fresh_until=fresh_until-interval '1 minute' WHERE root_id=$1`, s.input.RootID); err != nil {
						t.Fatal(err)
					}
				case "other-workload":
					in.Observation.Workload.UID = custodyID()
				case "other-scope":
					in.Authority.ScopeDigest = artifact.Digest{99}
				case "unaudited":
					if _, err := admin.Exec(ctx, `UPDATE policy_acceptance SET acknowledged_at=NULL,receipt_json=NULL WHERE root_id=$1`, s.input.RootID); err != nil {
						t.Fatal(err)
					}
				}
				if got, err := l.Tick(ctx, in); err == nil || len(got) != 0 {
					t.Fatal("trigger spent under", mode, got)
				}
				var spent int64
				if err := admin.QueryRow(ctx, `SELECT executions_spent FROM policy_acceptance WHERE root_id=$1`, s.input.RootID).Scan(&spent); err != nil || spent != 0 {
					t.Fatal("refused tick spent", spent, err)
				}
			})
		}
	})
	// Compile-time audit payload/receipt compatibility used by role-specific APIs.
	var _ audit.PolicyAcceptance = capture.PolicyAcceptance{}
}

// Only a fixture value for the SQL component boundary. The real cryptographic
// and provider composition is independently exercised by identity-integration.
func syntheticSubmissionCheck(a capture.PolicyAdmission, now time.Time) capture.SubmissionCheck {
	return capture.SubmissionCheck{Submission: a.Submission, RootID: a.RootID, InstallationID: a.Authority.InstallationID, IssuerEpoch: a.Recovery.IssuerEpoch, KeyID: "synthetic-signature-key", TrustRevision: identity.Revision{UID: "synthetic-signing-trust", Generation: 1, Digest: artifact.Digest{91}}, VerifiedAt: now, ValidUntil: identity.Earlier(now.Add(5*time.Second), a.Submission.ExpiresAt)}
}
