package identity

import (
	"testing"
	"time"
)

// ADR-249: step-up comes only from the signed acr/auth_time and the
// protected policy, for humans, and ends at auth_time+MaxAge or earlier.
func TestStepUpAssurance(t *testing.T) {
	c, p, now := fixture()
	p.StepUp = StepUpPolicy{ACRValues: []string{"gold"}, MaxAge: 5 * time.Minute}
	if p.Validate(now) != nil {
		t.Fatal("valid step-up policy rejected")
	}
	c.ACR, c.AuthTime = "gold", now.Add(-time.Minute)
	i, err := Admit(c, p, now)
	if err != nil || !i.SteppedUp(now) || !i.Assurance.StepUpUntil.Equal(Earlier(c.AuthTime.Add(5*time.Minute), i.ValidUntil)) || i.Assurance.ACR != "gold" {
		t.Fatalf("stepped-up identity: %+v %v", i.Assurance, err)
	}
	if i.SteppedUp(i.Assurance.StepUpUntil) {
		t.Fatal("step-up outlives its end")
	}
	for name, mutate := range map[string]func(*Claims, *Policy){
		"other acr":        func(c *Claims, _ *Policy) { c.ACR = "silver" },
		"too old":          func(c *Claims, _ *Policy) { c.AuthTime = now.Add(-6 * time.Minute) },
		"no auth_time":     func(c *Claims, _ *Policy) { c.AuthTime = time.Time{} },
		"no policy":        func(_ *Claims, p *Policy) { p.StepUp = StepUpPolicy{} },
		"future auth_time": func(c *Claims, _ *Policy) { c.AuthTime = now.Add(time.Second) },
		"no acr":           func(c *Claims, _ *Policy) { c.ACR = "" },
		"workload identity": func(_ *Claims, p *Policy) {
			p.Clients = []Client{{"console", Workload, true}}
			p.EligibleSubjects = []Subject{{"developer", Workload}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cc, pp := c, p
			pp.Clients = append([]Client(nil), p.Clients...)
			mutate(&cc, &pp)
			i, err := Admit(cc, pp, now)
			if err == nil && i.SteppedUp(now) {
				t.Fatal("step-up without the configured signed assurance")
			}
		})
	}
	for _, bad := range []StepUpPolicy{{ACRValues: []string{"gold"}, MaxAge: time.Second}, {ACRValues: []string{"gold"}, MaxAge: 2 * time.Hour}, {MaxAge: time.Minute}, {ACRValues: []string{"a", "a"}, MaxAge: time.Minute}} {
		pp := p
		pp.StepUp = bad
		if pp.Validate(now) == nil {
			t.Fatal("invalid step-up policy accepted", bad)
		}
	}
}
