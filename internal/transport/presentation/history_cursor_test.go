package presentation

import (
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestHistoryCursorBindsActorClientEntitlementAndOriginalSnapshot(t *testing.T) {
	svc, f, _ := historyOperations(t)
	now := svc.config.Now()
	svc.config.Now = func() time.Time { return now }
	in := ContextOperationInput{Target: WorkloadReference{ClusterID: "00000000-0000-4000-8000-000000000001", Namespace: "payments", Kind: "Deployment", Name: "api"}, Origin: "all"}
	page := value.HistoryPage{Target: authorization.WorkloadScope(in.Target.ClusterID, "ns", "workload"), AuthorizationRevision: f.i.Policy, SnapshotBefore: now, Next: &value.HistoryCursor{AcceptedAt: now.Add(-time.Minute), CaptureID: historyCapture}}
	token, err := svc.encodeHistoryCursor(in, f.i, page, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Cursor = *token
	decoded, err := svc.decodeHistoryCursor(in, f.i)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Target != page.Target || decoded.AuthorizationRevision != page.AuthorizationRevision {
		t.Fatal("cursor dropped resolved identity/revision")
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.Split(*token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), f.i.Principal.Subject) || strings.Contains(string(body), f.i.Principal.Issuer) {
		t.Fatal("cursor exposed caller identity instead of keyed binding")
	}
	for _, change := range []string{"client", "principal", "groups", "policy", "scope"} {
		actor := f.i
		switch change {
		case "client":
			actor.Principal.ClientID = "other-client"
		case "principal":
			actor.Principal.Subject = "other"
		case "groups":
			actor.Groups = []string{"other"}
		case "scope":
			actor.Scopes = []string{"other"}
		case "policy":
			actor.Policy.Generation++
		}
		if _, err = svc.decodeHistoryCursor(in, actor); err == nil {
			t.Fatal("cursor accepted changed", change)
		}
	}
	forged := in
	forged.Cursor = forged.Cursor[:len(forged.Cursor)-1] + "!"
	if _, err = svc.decodeHistoryCursor(forged, f.i); err == nil {
		t.Fatal("cursor accepted forged MAC")
	}
	now = now.Add(10 * time.Minute)
	next, err := svc.encodeHistoryCursor(in, f.i, page, decoded)
	if err != nil {
		t.Fatal(err)
	}
	in.Cursor = *next
	continued, err := svc.decodeHistoryCursor(in, f.i)
	if err != nil || !continued.ExpiresAt.Equal(decoded.ExpiresAt) || !continued.SnapshotBefore.Equal(decoded.SnapshotBefore) {
		t.Fatal("page renewed original cursor", err)
	}
	now = decoded.ExpiresAt
	if _, err = svc.decodeHistoryCursor(in, f.i); err == nil {
		t.Fatal("expired cursor remained usable")
	}
}
