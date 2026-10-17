package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// InstalledConfigurationProviderEffects owns the worker's two fixed finite
// provider credentials. Files, SQL pool and native readers remain owned by the
// enclosing worker until CloseAndJoin returns after actual local completion. This does not select an audit
// backend, launch a workload or change the installed command.
type InstalledConfigurationProviderEffects struct {
	input           contracts.HubWorkerDeployment
	files           *os.Root
	reader          *kubernetes.ConfigurationWorkerProviderReader
	recovery        *postgres.RecoveryReader
	effects         *configurationProviderEffects
	admission       *fleetapp.WorkerRuntimeAdmission
	root            context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	started, closed bool
	joined          sync.WaitGroup
	closeWait       sync.Once
	closeDone       chan struct{}
}

func NewInstalledConfigurationProviderEffects(ctx context.Context, input contracts.HubWorkerDeployment, files *os.Root, reader *kubernetes.ConfigurationWorkerProviderReader, recovery *postgres.RecoveryReader, admission *fleetapp.WorkerRuntimeAdmission) (*InstalledConfigurationProviderEffects, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || reader == nil || recovery == nil || admission == nil || input.ProviderAuthentication == nil || !reader.MatchesInput(input) || providerconfig.ValidateConfigurationProviderAuthentication(input, *input.ProviderAuthentication, time.Now()) != nil {
		return nil, ErrKeyService
	}
	raw, err := json.Marshal(input)
	var cloned contracts.HubWorkerDeployment
	if err != nil || json.Unmarshal(raw, &cloned) != nil {
		return nil, ErrKeyService
	}
	root, cancel := context.WithCancel(ctx)
	s := &InstalledConfigurationProviderEffects{input: cloned, files: files, reader: reader, recovery: recovery, admission: admission, root: root, cancel: cancel, closeDone: make(chan struct{})}
	base := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	s.effects, err = newConfigurationProviderEffects(root, cloned, *cloned.ProviderAuthentication, s.projectedJWT, s.current, base, time.Now)
	if err != nil {
		cancel()
		return nil, err
	}
	return s, nil
}

func (s *InstalledConfigurationProviderEffects) Sealer() *Sealer {
	if s == nil || s.effects == nil {
		return nil
	}
	return s.effects.seal
}
func (s *InstalledConfigurationProviderEffects) Opener() *Opener {
	if s == nil || s.effects == nil {
		return nil
	}
	return s.effects.open
}

func (s *InstalledConfigurationProviderEffects) borrow(ctx context.Context) (context.Context, func(), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrKeyService
	}
	s.mu.Lock()
	if s.closed || s.root.Err() != nil {
		s.mu.Unlock()
		return nil, nil, ErrKeyService
	}
	s.joined.Add(1)
	s.mu.Unlock()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	done := make(chan struct{})
	stop := context.AfterFunc(s.root, func() { cancel(); close(done) })
	return call, func() {
		cancel()
		if !stop() {
			<-done
		}
		s.joined.Done()
	}, nil
}
func (s *InstalledConfigurationProviderEffects) projectedJWT(ctx context.Context) ([]byte, error) {
	b, err := mounts.Read(ctx, s.files, contracts.ConfigurationProviderTokenFile, 16<<10)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, ErrKeyService
	}
	return b, nil
}
func (s *InstalledConfigurationProviderEffects) mounted(ctx context.Context) (contracts.ConfigurationRuntimeCredentialManifest, map[string][]byte, error) {
	var zero contracts.ConfigurationRuntimeCredentialManifest
	raw, err := mounts.Read(ctx, s.files, "deployment.json", contracts.OwnerDeploymentMaxBytes)
	if err != nil {
		return zero, nil, ErrKeyService
	}
	defer clear(raw)
	input, err := contracts.DecodeHubWorkerDeployment(bytes.NewReader(raw))
	if err != nil || !s.reader.MatchesInput(input) {
		return zero, nil, ErrKeyService
	}
	out := map[string][]byte{}
	ok := false
	defer func() {
		if !ok {
			for _, b := range out {
				clear(b)
			}
		}
	}()
	for _, name := range []string{contracts.ConfigurationRuntimeRoleManifestFile, "sql-fleet.json", "sql-configuration.json", "sql-audit.json", contracts.ConfigurationProviderAuditCredentialFile} {
		maximum := int64(contracts.ConfigurationRuntimeRoleMaxBytes)
		if name == contracts.ConfigurationProviderAuditCredentialFile {
			maximum = 32 << 10
		}
		b, e := mounts.Read(ctx, s.files, name, maximum)
		if e != nil || len(b) == 0 {
			clear(b)
			return zero, nil, ErrKeyService
		}
		out[name] = b
	}
	manifest, err := contracts.DecodeConfigurationRuntimeCredentialManifest(bytes.NewReader(out[contracts.ConfigurationRuntimeRoleManifestFile]))
	if err != nil || ctx.Err() != nil {
		return zero, nil, ErrKeyService
	}
	ok = true
	return manifest, out, nil
}

// Recovery reads are separate committed read-only SQL transactions. No SQL
// lock is retained across Kubernetes reads, provider HTTP or credential effects.
func (s *InstalledConfigurationProviderEffects) currentMaterial(ctx context.Context) (contracts.OwnerStorageCredential, time.Time, error) {
	var zero contracts.OwnerStorageCredential
	if s == nil || ctx == nil || ctx.Err() != nil || s.root.Err() != nil {
		return zero, time.Time{}, ErrKeyService
	}
	first, err := s.recovery.RecoveryState(ctx)
	if err != nil || !first.Valid(time.Now()) || first.InstallationID != s.input.InstallationID {
		return zero, time.Time{}, ErrKeyService
	}
	call, end := context.WithDeadline(ctx, first.FreshUntil)
	defer end()
	manifest, mounted, err := s.mounted(call)
	if err != nil {
		return zero, time.Time{}, err
	}
	defer func() {
		for _, b := range mounted {
			clear(b)
		}
	}()
	until, err := s.reader.Verify(call, first.IssuerEpoch, manifest, mounted)
	until = identity.Earlier(until, first.FreshUntil)
	if err != nil {
		return zero, time.Time{}, ErrKeyService
	}
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	last, err := s.recovery.RecoveryState(call)
	until = identity.Earlier(until, last.FreshUntil)
	if err != nil || !last.Valid(time.Now()) || last.InstallationID != first.InstallationID || last.IssuerEpoch != first.IssuerEpoch || last.Revision != first.Revision || call.Err() != nil || !time.Now().Before(until) {
		return zero, time.Time{}, ErrKeyService
	}
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(mounted[contracts.ConfigurationProviderAuditCredentialFile]))
	if err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, time.Time{}, ErrKeyService
	}
	return credential, until, nil
}
func (s *InstalledConfigurationProviderEffects) current(ctx context.Context) (time.Time, error) {
	_, until, err := s.currentMaterial(ctx)
	return until, err
}

// ReadAuditCredentials verifies the actual selected Secret and mounted bytes.
// It grants no conditional-create/deletion assurance for an unqualified store.
func (s *InstalledConfigurationProviderEffects) ReadAuditCredentials(ctx context.Context) (contracts.OwnerStorageCredential, time.Time, error) {
	var zero contracts.OwnerStorageCredential
	call, end, err := s.borrow(ctx)
	if err != nil {
		return zero, time.Time{}, err
	}
	defer end()
	return s.currentMaterial(call)
}

// Start beside the independent fleet source loop, never before it as a blocking
// prerequisite: a missing current recovery observation keeps this pair unusable
// while fleet reconciliation can still refresh its own original accepted source.
func (s *InstalledConfigurationProviderEffects) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	s.mu.Lock()
	if s.started || s.closed || s.root.Err() != nil {
		s.mu.Unlock()
		return ErrKeyService
	}
	s.started = true
	s.joined.Add(1)
	s.mu.Unlock()
	defer s.joined.Done()
	call, end := context.WithCancel(ctx)
	done := make(chan struct{})
	stop := context.AfterFunc(s.root, func() { end(); close(done) })
	defer func() {
		end()
		if !stop() {
			<-done
		}
	}()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-call.Done():
			return ErrKeyService
		case <-timer.C:
		}
		for _, slot := range []*ownerProviderLifetime{s.effects.wrap, s.effects.unwrap} {
			if call.Err() != nil {
				return ErrKeyService
			}
			_ = slot.refreshConfiguration(call, s)
		}
	}
}

// A deadline/error retains all ownership. The enclosing worker uses
// CloseAndJoin to preserve this result while joining without new provider I/O.
func (s *InstalledConfigurationProviderEffects) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	s.closeWait.Do(func() { go func() { s.joined.Wait(); close(s.closeDone) }() })
	if err := s.effects.close(call); err != nil {
		return err
	}
	select {
	case <-s.closeDone:
		return nil
	case <-call.Done():
		return ErrKeyService
	}
}

// CloseAndJoin preserves the one bounded close result. Waiting after that
// interval is local ownership finalization, never another provider operation.
func (s *InstalledConfigurationProviderEffects) CloseAndJoin(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	result := s.Close(ctx)
	<-s.closeDone
	s.effects.joinClosed()
	return result
}
