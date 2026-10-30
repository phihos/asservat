package planning

import (
	"asservat.local/asservat/internal/domain/authorization"
	"encoding/json"
	"testing"
)

func TestSourceSnapshotCompilerUsesExactCaptureAuditExecutorPath(t *testing.T) {
	in, now := sourceSnapshotInput(t)
	in.Snapshot.TriggerKind = "policy"
	in.Executor = authorization.PolicyPrincipal("10000000-0000-4000-8000-000000000001", in.Snapshot.PolicyUID)
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal("valid source snapshot plan", err)
	}
	// SQL82's capture_audit_payload_matches uses case-sensitive JSON paths
	// {executor,issuer/subject/clientID/identityType}. Go struct decoding is
	// deliberately not used here because it accepts different field casing.
	var scope map[string]json.RawMessage
	if json.Unmarshal(plan.CanonicalScope, &scope) != nil {
		t.Fatal("canonical scope JSON")
	}
	var executor map[string]string
	if json.Unmarshal(scope["executor"], &executor) != nil {
		t.Fatal("canonical source snapshot lacks exact lowercase SQL executor path")
	}
	if executor["issuer"] != in.Executor.Issuer || executor["subject"] != in.Executor.Subject || executor["clientID"] != in.Executor.ClientID || executor["identityType"] != string(in.Executor.Kind) {
		t.Fatal("capture audit executor binding differs", executor)
	}
	if _, exists := scope["Executor"]; exists {
		t.Fatal("duplicate alternate-case audit identity")
	}
}
