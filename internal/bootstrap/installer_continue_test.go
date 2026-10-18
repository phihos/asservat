package bootstrap

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestInstallerActivationClosesHistoryBeforeRuntimeWork(t *testing.T) {
	record, receipt := audit.InitialInstallation{}, audit.Receipt{}
	record.Scope.InstallationID = "retained-installation"
	receipt.Key, receipt.Version = "retained-audit", "original-version"
	readFailure := errors.New("observation failed")
	for _, tc := range []struct {
		name        string
		observation fleetapp.InitialInstallationObservation
		err         error
		want        bool
	}{
		{"activated", fleetapp.InitialInstallationObservation{Disposition: fleetapp.InitialInstallationActivated, Record: &record, AuditReceipt: &receipt}, nil, true},
		{"not activated", fleetapp.InitialInstallationObservation{Disposition: fleetapp.InitialInstallationAudited, Record: &record, AuditReceipt: &receipt}, nil, false},
		{"missing record", fleetapp.InitialInstallationObservation{Disposition: fleetapp.InitialInstallationActivated, AuditReceipt: &receipt}, nil, false},
		{"missing receipt", fleetapp.InitialInstallationObservation{Disposition: fleetapp.InitialInstallationActivated, Record: &record}, nil, false},
		{"read failure", fleetapp.InitialInstallationObservation{}, readFailure, false},
		{"cancellation", fleetapp.InitialInstallationObservation{}, context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			history := initialHandoverHistoryFunc(func(context.Context) (fleetapp.InitialInstallationObservation, error) {
				events = append(events, "observe")
				return tc.observation, tc.err
			})
			gotRecord, gotReceipt, err := observeInstallerActivation(context.Background(), history, func() { events = append(events, "closed") })
			events = append(events, "caller resumes")
			if !reflect.DeepEqual(events, []string{"observe", "closed", "caller resumes"}) {
				t.Fatal("passive pool was retained into runtime work", events)
			}
			if (err == nil) != tc.want || tc.err != nil && !errors.Is(err, tc.err) || err != nil && !errors.Is(err, mounts.ErrUnavailable) {
				t.Fatal("activation acceptance changed", err)
			}
			if tc.want && (!reflect.DeepEqual(gotRecord, record) || !reflect.DeepEqual(gotReceipt, receipt)) {
				t.Fatal("original activation identity replaced")
			}
		})
	}
}

// The operator's stop message names the step and class, never inner text.
func TestInstallerContinuationStopIsFixed(t *testing.T) {
	err := &InstallerContinuationStop{Step: "bridge/probe", Err: errors.Join(cfg.ErrChanged, errors.New("secret-bearing detail"))}
	if err.Error() != "installer continuation stopped at bridge/probe (changed)" || !errors.Is(err, cfg.ErrChanged) {
		t.Fatal(err.Error())
	}
	nested := &InstallerContinuationStop{Step: "worker/roles-provision", Err: &postgres.ProvisionStop{Step: "authenticate:configuration-source", Err: cfg.ErrUnavailable}}
	if nested.Error() != "installer continuation stopped at worker/roles-provision/authenticate:configuration-source (unavailable)" {
		t.Fatal(nested.Error())
	}
}

func TestInstallerContinuationBudgetStopNamesSafeCounts(t *testing.T) {
	plan, _ := contracts.InstalledSQLConnectionPlan(1)
	_, err := plan.Validate(0, contracts.SQLServerCapacity{MaxConnections: 48, SuperuserReserved: 3})
	stop := &InstallerContinuationStop{Step: "open/sql-budget", Err: errors.Join(err, errors.New("secret SQL detail"))}
	if !strings.Contains(stop.Error(), "requires 112 connections, 45 configured") || strings.Contains(stop.Error(), "secret") || !errors.Is(stop, contracts.ErrSQLConnectionBudget) {
		t.Fatal(stop.Error())
	}
}

// A lookup-only replay hides the cause; the stop names the first attempt too.
func TestConvergeStopNamesFirstAttempt(t *testing.T) {
	steps := []error{&postgres.ProvisionStop{Step: "complete:configuration-fleet", Err: cfg.ErrUnavailable}, &postgres.ProvisionStop{Step: "role:configuration-fleet", Err: cfg.ErrChanged}}
	n := 0
	err := converge(context.Background(), time.Minute, func() error { n++; return steps[n-1] })
	stop := &InstallerContinuationStop{Step: "worker/roles-provision", Err: err}
	if want := "installer continuation stopped at worker/roles-provision/role:configuration-fleet after 2 attempts; first complete:configuration-fleet (unavailable) (changed)"; stop.Error() != want || !errors.Is(err, cfg.ErrChanged) {
		t.Fatal(stop.Error())
	}
}

func TestValidPublicExposure(t *testing.T) {
	f := contracts.InstallerFederationSettings{NodePort: 31443, KeyServiceNodePort: 31444, OwnerNodePort: 31446, OwnerOperationNodePort: 31447}
	for _, tc := range []struct {
		e    contracts.InstallerPublicExposure
		want bool
	}{
		{contracts.InstallerPublicExposure{ServiceType: "NodePort"}, true},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31450}, true},
		{contracts.InstallerPublicExposure{ServiceType: "LoadBalancer"}, true},
		{contracts.InstallerPublicExposure{ServiceType: "LoadBalancer", NodePort: 31450}, false},
		{contracts.InstallerPublicExposure{ServiceType: "ClusterIP"}, false},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 29999}, false},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 32768}, false},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31443}, false},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31444}, false},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31446}, false},
		{contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31447}, false},
	} {
		if got := validPublicExposure(tc.e, f); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.e, got, tc.want)
		}
	}
}
