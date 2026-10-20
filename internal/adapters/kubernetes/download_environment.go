package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"net/url"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	admission "k8s.io/api/admissionregistration/v1"
)

const downloadEnvironmentDenial = "Asservat processing policy administrator is required."

type DownloadEnvironmentProtection struct{ *configMapProtection }

func DownloadEnvironmentAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-processing-namespace", downloadEnvironmentDenial)
}
func NewDownloadEnvironmentProtection(observer, probe *PermissionClient, plan cfg.ConfigMapAdministration, pin GuardPin) (*DownloadEnvironmentProtection, error) {
	g, e := newConfigMapProtection(observer, probe, plan, pin, "protected-processing-namespace", downloadEnvironmentDenial)
	if e != nil {
		return nil, e
	}
	return &DownloadEnvironmentProtection{g}, nil
}

// The installed paths are independently accepted deployment pins. Reading a
// mutable policy can permit or remove an existing path, never invent its
// placement, worker profile or hub pool. Inputs are copied and are not endpoints.
type DownloadEnvironmentSource struct {
	client                        *PermissionClient
	protection                    *DownloadEnvironmentProtection
	name, uid, root, installation string
	paths                         map[string]privacy.DownloadPath
}

func NewDownloadEnvironmentSource(c *PermissionClient, p *DownloadEnvironmentProtection, name, uid, root, installation string, installed []privacy.DownloadPath) (*DownloadEnvironmentSource, error) {
	if c == nil || p == nil || p.configMapProtection == nil || p.observer != c || p.plan.SourceName != name || !installationRefValid(name, uid) || !authorization.UUID(uid) || !authorization.UUID(root) || !authorization.UUID(installation) || installed == nil || len(installed) > 32 {
		return nil, privacy.ErrInvalid
	}
	s := &DownloadEnvironmentSource{c, p, name, uid, root, installation, make(map[string]privacy.DownloadPath, len(installed))}
	for _, path := range installed {
		if !path.Valid() {
			return nil, privacy.ErrInvalid
		}
		if _, ok := s.paths[path.ID]; ok {
			return nil, privacy.ErrInvalid
		}
		s.paths[path.ID] = path
	}
	return s, nil
}
func validProcessingIssuer(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && identity.Text(s, 2048)
}
func processingRevision(w contracts.DownloadEnvironmentRevision) (identity.Revision, error) {
	var out identity.Revision
	b, e := hex.DecodeString(w.SHA256)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != w.SHA256 {
		return out, privacy.ErrInvalid
	}
	out.UID = w.UID
	out.Generation = w.Generation
	copy(out.Digest[:], b)
	if !out.Valid() {
		return identity.Revision{}, privacy.ErrInvalid
	}
	return out, nil
}
func (s *DownloadEnvironmentSource) snapshot(ctx context.Context) (privacy.DownloadPolicy, error) {
	var out privacy.DownloadPolicy
	data, _, e := s.client.installationConfig(ctx, s.name, s.uid)
	if e != nil || len(data) != 1 || len(data[contracts.DownloadEnvironmentFile]) < 1 || len(data[contracts.DownloadEnvironmentFile]) > contracts.DownloadEnvironmentMaxBytes {
		return out, privacy.ErrUnavailable
	}
	b := []byte(data[contracts.DownloadEnvironmentFile])
	var w contracts.DownloadEnvironmentSettings
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil {
		return out, privacy.ErrInvalid
	}
	encoded, e := json.Marshal(w)
	a, z := jsontext.Value(b), jsontext.Value(encoded)
	if e != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || w.Format != contracts.DownloadEnvironmentFormat || w.RootID != s.root || w.InstallationID != s.installation || w.Paths == nil || w.Clients == nil || w.Operators == nil || w.PermittedRegions == nil {
		return out, privacy.ErrInvalid
	}
	out = privacy.DownloadPolicy{RootID: w.RootID, InstallationID: w.InstallationID, RecoveryEpoch: w.RecoveryEpoch, Revision: identity.Revision{UID: s.uid, Generation: w.Revision, Digest: sha256.Sum256(a)}, Suspended: w.Suspended, PermittedRegions: w.PermittedRegions, Paths: make([]privacy.DownloadPath, 0, len(w.Paths)), Clients: make([]privacy.DownloadClient, 0, len(w.Clients)), Operators: make([]privacy.ProcessingOperator, 0, len(w.Operators))}
	for _, p := range w.Paths {
		worker, e := processingRevision(p.WorkerConfiguration)
		if e != nil {
			return privacy.DownloadPolicy{}, e
		}
		hub, e := processingRevision(p.HubConfiguration)
		if e != nil {
			return privacy.DownloadPolicy{}, e
		}
		path := privacy.DownloadPath{ID: p.ID, TargetClusterID: p.TargetClusterID, StoreID: p.StoreID, StorageRegion: p.StorageRegion, AcquisitionClusterID: p.AcquisitionClusterID, AcquisitionRegion: p.AcquisitionRegion, ConnectorClusterID: p.ConnectorClusterID, ConnectorRegion: p.ConnectorRegion, HubClusterID: p.HubClusterID, HubRegion: p.HubRegion, WorkerConfiguration: worker, HubConfiguration: hub}
		installed, ok := s.paths[path.ID]
		if !ok || installed != path {
			return privacy.DownloadPolicy{}, privacy.ErrUnavailable
		}
		out.Paths = append(out.Paths, path)
	}
	for _, c := range w.Clients {
		if !validProcessingIssuer(c.Issuer) {
			return privacy.DownloadPolicy{}, privacy.ErrInvalid
		}
		out.Clients = append(out.Clients, privacy.DownloadClient{Issuer: c.Issuer, ID: c.ID, Kind: identity.Kind(c.Kind), DataClasses: c.DataClasses, PrivacyClasses: c.PrivacyClasses, EvidenceTypes: c.EvidenceTypes, Purposes: c.Purposes, PathIDs: c.PathIDs})
	}
	for _, o := range w.Operators {
		if !validProcessingIssuer(o.Issuer) {
			return privacy.DownloadPolicy{}, privacy.ErrInvalid
		}
		out.Operators = append(out.Operators, privacy.ProcessingOperator{Issuer: o.Issuer, ClientID: o.ClientID, Kind: o.Kind, ID: o.ID})
	}
	if !out.WellFormed() {
		return privacy.DownloadPolicy{}, privacy.ErrInvalid
	}
	return out, nil
}

func (s *DownloadEnvironmentSource) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	var zero privacy.DownloadPolicy
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, privacy.ErrUnavailable
	}
	start := s.client.now()
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	// Fixed stage names for diagnostics; the classes are unchanged.
	guard, until, e := s.protection.current(call)
	if e != nil {
		return zero, connectorAPIStage("protection", errors.Join(privacy.ErrUnavailable, e))
	}
	p, e := s.snapshot(call)
	if e != nil {
		return zero, connectorAPIStage("snapshot", e)
	}
	again, e := s.snapshot(call)
	if e != nil || again.Revision != p.Revision {
		return zero, connectorAPIStage("snapshot-again", privacy.ErrUnavailable)
	}
	if _, e = checkAdmissionGuard(call, s.client, s.protection.plan.Name, s.protection.pin, s.protection.policy, s.protection.binding); e != nil {
		return zero, connectorAPIStage("guard", errors.Join(privacy.ErrUnavailable, e))
	}
	p.ProtectionDigest = artifact.Digest(guard)
	p.ObservedAt = start
	p.FreshUntil = identity.Earlier(until, start.Add(5*time.Second))
	if end, ok := call.Deadline(); ok {
		p.FreshUntil = identity.Earlier(p.FreshUntil, end)
	}
	if !p.Valid(s.client.now()) || call.Err() != nil {
		return zero, privacy.ErrUnavailable
	}
	return p, nil
}
