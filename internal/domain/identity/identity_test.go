package identity

import (
	"testing"
	"time"
)

func fixture() (Claims, Policy, time.Time) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	c := Claims{Issuer: "https://id.example.invalid", Subject: "developer", ClientID: "console", Scopes: []string{"evidence:read"}, Groups: []string{"team-a"}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), KeyUntil: now.Add(time.Minute)}
	p := Policy{Revision: Revision{"policy", 1, [32]byte{1}}, Issuer: c.Issuer, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []Client{{"console", Human, true}}, EligibleGroups: []string{"team-a"}, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute}
	return c, p, now
}

func TestOrganizationAdmission(t *testing.T) {
	c, p, now := fixture()
	i, err := Admit(c, p, now)
	if err != nil || i.Principal.Kind != Human || !i.ValidUntil.Equal(p.FreshUntil) {
		t.Fatalf("admission/freshness: %v", err)
	}
	c.Groups[0] = "mutated"
	c.Scopes[0] = "mutated"
	if i.Groups[0] != "team-a" || i.Scopes[0] != "evidence:read" {
		t.Fatal("mutable claims escaped")
	}
	tests := map[string]func(*Claims, *Policy){
		"foreign issuer":                        func(c *Claims, p *Policy) { c.Issuer = "https://other.example.invalid" },
		"eligible issuer is not membership":     func(c *Claims, p *Policy) { c.Groups = []string{"outsiders"} },
		"unregistered client":                   func(c *Claims, p *Policy) { c.ClientID = "attacker" },
		"ambiguous identity class":              func(c *Claims, p *Policy) { p.Clients[0].ClassQualified = false },
		"duplicate client":                      func(c *Claims, p *Policy) { p.Clients = append(p.Clients, p.Clients[0]) },
		"stale policy":                          func(c *Claims, p *Policy) { p.FreshUntil = now },
		"future policy":                         func(c *Claims, p *Policy) { p.ObservedAt = now.Add(time.Second) },
		"unbounded policy":                      func(c *Claims, p *Policy) { p.FreshUntil = now.Add(61 * time.Second) },
		"unqualified groups":                    func(c *Claims, p *Policy) { p.GroupsAtIssueQualified = false },
		"duplicate groups":                      func(c *Claims, p *Policy) { c.Groups = append(c.Groups, c.Groups[0]) },
		"stale groups":                          func(c *Claims, p *Policy) { c.IssuedAt = now.Add(-5 * time.Minute) },
		"fresh signature cannot refresh groups": func(c *Claims, p *Policy) { c.IssuedAt = now.Add(-6 * time.Minute); c.KeyUntil = now.Add(time.Minute) },
		"expired key":                           func(c *Claims, p *Policy) { c.KeyUntil = now },
		"expired token":                         func(c *Claims, p *Policy) { c.ExpiresAt = now },
		"future token":                          func(c *Claims, p *Policy) { c.IssuedAt = now.Add(time.Second) },
		"controls in subject":                   func(c *Claims, p *Policy) { c.Subject = "secret\nsecond-line" },
		"invalid revision":                      func(c *Claims, p *Policy) { p.Revision.Digest = [32]byte{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c, p, now := fixture()
			mutate(&c, &p)
			if _, err := Admit(c, p, now); err == nil {
				t.Fatal("unsafe identity admitted")
			}
		})
	}
}

func TestIdentityDeadlinesAndKinds(t *testing.T) {
	for _, which := range []string{"token", "key", "group", "policy"} {
		t.Run(which, func(t *testing.T) {
			c, p, now := fixture()
			end := now.Add(time.Second)
			switch which {
			case "token":
				c.ExpiresAt = end
			case "key":
				c.KeyUntil = end
			case "group":
				c.IssuedAt = end.Add(-p.GroupMaxAge)
			case "policy":
				p.FreshUntil = end
			}
			i, err := Admit(c, p, now)
			if err != nil || !i.ValidUntil.Equal(end) || i.Valid(end) {
				t.Fatalf("deadline extended: %v", err)
			}
		})
	}
	c, p, now := fixture()
	p.EligibleGroups = nil
	p.EligibleSubjects = []Subject{{c.Subject, Human}}
	p.Clients[0].Kind = Workload
	if _, err := Admit(c, p, now); err == nil {
		t.Fatal("workload reused human eligibility")
	}
	p.EligibleSubjects[0].Kind = Workload
	if i, err := Admit(c, p, now); err != nil || i.Principal.Kind != Workload {
		t.Fatalf("explicit workload identity rejected: %v", err)
	}
}
