package fleet

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

func TestFleetOperatorSeparatesOperatorsAndClients(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	id := "11111111-1111-4111-8111-111111111111"
	revision := identity.Revision{UID: "synthetic-settings", Generation: 1, Digest: [32]byte{1}}
	settings := Administration{InstallationID: id, IssuerEpoch: id, Issuer: "https://identity.example.test", Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"console"}, Groups: []string{"platform"}, DeliveryProfiles: []string{"enrollment"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 1024, MaxClusters: 32}
	actor := identity.Identity{Principal: identity.Principal{Issuer: settings.Issuer, Subject: "developer", ClientID: "console", Kind: identity.Human}, Policy: revision, Groups: []string{"platform"}, VerifiedAt: now, ValidUntil: now.Add(10 * time.Second)}
	for _, mode := range []string{"group", "subject", "not-operator", "issuer", "unapproved-client", "stale-identity", "stale-settings", "suspended", "duplicate-operator", "history-limit", "identity-kind"} {
		t.Run(mode, func(t *testing.T) {
			a, i := settings, actor
			switch mode {
			case "subject":
				a.Groups = nil
				a.Subjects = []identity.Subject{{ID: i.Principal.Subject, Kind: i.Principal.Kind}}
			case "not-operator":
				i.Groups = []string{"workload-maintainers"}
			case "issuer":
				i.Principal.Issuer = "https://other.example.test"
			case "unapproved-client":
				i.Principal.ClientID = "agent"
			case "stale-identity":
				i.ValidUntil = now
			case "stale-settings":
				a.FreshUntil = now
			case "suspended":
				a.Suspended = true
			case "duplicate-operator":
				a.Subjects = []identity.Subject{{ID: "a", Kind: identity.Human}, {ID: "a", Kind: identity.Human}}
			case "history-limit":
				a.MaxBootstrapHistory = 1
			case "identity-kind":
				a.Groups = nil
				a.Subjects = []identity.Subject{{ID: i.Principal.Subject, Kind: identity.Human}}
				i.Principal.Kind = identity.Workload
			}
			operator := a.Valid(now) && i.Valid(now) && a.Operator(i)
			if operator != (mode == "group" || mode == "subject") {
				t.Fatal("fleet operator", mode, operator)
			}
		})
	}
}
