package privacy

import (
	"fmt"
	"strings"
	"testing"
)

func processingOrganizationFixture() ProcessingOrganization {
	return ProcessingOrganization{ID: "operator-storage", Name: "Configured organization", Activities: []string{"Evidence storage"}, Regions: []string{"operator-region"}}
}

func TestProcessingOrganizationsAreBoundedDeclarations(t *testing.T) {
	for _, declarations := range [][]ProcessingOrganization{nil, {}, {processingOrganizationFixture()}} {
		if !ProcessingOrganizationsValid(declarations) {
			t.Fatal("valid optional declarations refused")
		}
	}
	for name, change := range map[string]func(*ProcessingOrganization){
		"empty ID":        func(o *ProcessingOrganization) { o.ID = "" },
		"long ID":         func(o *ProcessingOrganization) { o.ID = strings.Repeat("i", 65) },
		"long name":       func(o *ProcessingOrganization) { o.Name = strings.Repeat("n", 161) },
		"control":         func(o *ProcessingOrganization) { o.Name += "\n" },
		"no activities":   func(o *ProcessingOrganization) { o.Activities = nil },
		"empty activity":  func(o *ProcessingOrganization) { o.Activities = []string{""} },
		"long activity":   func(o *ProcessingOrganization) { o.Activities = []string{strings.Repeat("a", 129)} },
		"many activities": func(o *ProcessingOrganization) { o.Activities = make([]string, 9) },
		"repeat activity": func(o *ProcessingOrganization) { o.Activities = []string{"Storage", "Storage"} },
		"missing regions": func(o *ProcessingOrganization) { o.Regions = nil },
		"long region":     func(o *ProcessingOrganization) { o.Regions = []string{strings.Repeat("r", 129)} },
		"many regions":    func(o *ProcessingOrganization) { o.Regions = make([]string, 17) },
		"repeat region":   func(o *ProcessingOrganization) { o.Regions = []string{"local", "local"} },
	} {
		t.Run(name, func(t *testing.T) {
			organization := processingOrganizationFixture()
			change(&organization)
			if ProcessingOrganizationsValid([]ProcessingOrganization{organization}) {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	if ProcessingOrganizationsValid([]ProcessingOrganization{processingOrganizationFixture(), processingOrganizationFixture()}) {
		t.Fatal("duplicate organization IDs accepted")
	}
	maximum := processingOrganizationFixture()
	maximum.ID, maximum.Name = strings.Repeat("i", 64), strings.Repeat("n", 160)
	maximum.Activities = []string{}
	for i := range 8 {
		maximum.Activities = append(maximum.Activities, fmt.Sprintf("%03d", i)+strings.Repeat("a", 125))
	}
	maximum.Regions = []string{}
	for i := range 16 {
		maximum.Regions = append(maximum.Regions, fmt.Sprintf("%03d", i)+strings.Repeat("r", 125))
	}
	declarations := make([]ProcessingOrganization, 16)
	for i := range declarations {
		declarations[i] = maximum
		declarations[i].ID = fmt.Sprintf("%03d", i) + maximum.ID[3:]
	}
	if !ProcessingOrganizationsValid(declarations) || ProcessingOrganizationsValid(append(declarations, processingOrganizationFixture())) {
		t.Fatal("organization count or field boundaries")
	}
	organization := processingOrganizationFixture()
	organization.Regions = []string{}
	if !ProcessingOrganizationsValid([]ProcessingOrganization{organization}) {
		t.Fatal("explicit empty region list refused")
	}
}

func TestProcessingOrganizationsDoNotGrantDownloadAccess(t *testing.T) {
	policy, principal, now := downloadPolicyFixture()
	path, permitted := policy.Select(principal, policy.Paths[0].TargetClusterID, policy.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", now)
	policy.Processors = []ProcessingOrganization{processingOrganizationFixture()}
	selected, allowed := policy.Select(principal, policy.Paths[0].TargetClusterID, policy.Paths[0].StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", now)
	if !permitted || !allowed || path != selected {
		t.Fatal("report metadata changed the selected technical path")
	}
	policy.Clients = []DownloadClient{}
	if _, allowed := policy.Select(principal, path.TargetClusterID, path.StoreID, "diagnostics", "metadata", "potentialPersonalData", "context", now); allowed {
		t.Fatal("organization declaration granted disclosure")
	}
	policy.Processors = []ProcessingOrganization{processingOrganizationFixture(), processingOrganizationFixture()}
	if policy.WellFormed() {
		t.Fatal("policy accepted duplicate organization declarations")
	}
}
