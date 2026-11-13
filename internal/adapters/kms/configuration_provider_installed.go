package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConfigurationProviderInput is the hub-worker's Helm-rendered OpenBao
// configuration plus the generated installation IDs it scopes audits by.
// `setup` creates the auth roles and policies with the same names.
type ConfigurationProviderInput struct {
	InstallationID, ClusterID, NamespaceUID, OwnerSourceUID string
	Namespace, ServiceAccount                               string
	Endpoint                                                string
	Roots                                                   [][]byte
	AuthMount                                               string
	AuditMount, AuditKey                                    string
	Roles                                                   contracts.HubWorkerProviderRoles
	WorkerConfigurationAudit, ContextDeletionSigning        contracts.OwnerPublicTransit
	// TokenFile and AuditCredentialFile are fixed files of Files.
	TokenFile, AuditCredentialFile string
}

func (in ConfigurationProviderInput) cleanup() bool { return in.Roles.CleanupWrap != "" }

// InstalledConfigurationProviderEffects owns the worker's fixed finite
// provider credentials. Every login and renewal is bounded by a current SQL
// recovery observation; the audit object-store credential is the mounted
// Secret file. Files and the SQL pool remain owned by the enclosing worker
// until CloseAndJoin returns after actual local completion.
type InstalledConfigurationProviderEffects struct {
	input           ConfigurationProviderInput
	files           *os.Root
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

func NewInstalledConfigurationProviderEffects(ctx context.Context, input ConfigurationProviderInput, files *os.Root, recovery *postgres.RecoveryReader, admission *fleetapp.WorkerRuntimeAdmission) (*InstalledConfigurationProviderEffects, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || recovery == nil || admission == nil || !keyName.MatchString(input.AuditMount) || !keyName.MatchString(input.AuditKey) ||
		input.TokenFile == "" || input.AuditCredentialFile == "" || input.Roles.AuditWrap == "" || input.Roles.AuditUnwrap == "" ||
		input.cleanup() && (input.Roles.CleanupOpen == "" || input.Roles.CleanupVerify == "" || input.Roles.CleanupSign == "" || input.ContextDeletionSigning == (contracts.OwnerPublicTransit{})) {
		return nil, ErrKeyService
	}
	input.Roots = slices.Clone(input.Roots)
	root, cancel := context.WithCancel(ctx)
	s := &InstalledConfigurationProviderEffects{input: input, files: files, recovery: recovery, admission: admission, root: root, cancel: cancel, closeDone: make(chan struct{})}
	base := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	var err error
	s.effects, err = newConfigurationProviderEffects(root, input, s.projectedJWT, s.current, base, time.Now)
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

// AuditKeys seals and opens with another Transit key through the same two
// purpose-fixed audit lifetimes (ADR-204 decision 7: the worker configuration
// audit has its own key). It cannot name the configuration audit key itself;
// the provider policy, not this client, decides whether the key is usable.
// Every call still borrows the lifetimes' current tokens; the caller closes
// both clients.
func (s *InstalledConfigurationProviderEffects) AuditKeys(mount, key string) (*Sealer, *Opener, error) {
	if s == nil || s.effects == nil || s.effects.wrap == nil || s.effects.unwrap == nil || !keyName.MatchString(mount) || !keyName.MatchString(key) || mount == s.input.AuditMount && key == s.input.AuditKey {
		return nil, nil, ErrKeyService
	}
	wrap, err := newOwnerProviderEffectClient(s.effects.wrap, mount+"/encrypt/"+key)
	if err != nil {
		return nil, nil, err
	}
	seal := &Sealer{client: wrap, mount: mount, key: key, reference: mount + "/" + key}
	unwrap, err := newOwnerProviderEffectClient(s.effects.unwrap, mount+"/decrypt/"+key)
	if err != nil {
		seal.Close()
		return nil, nil, err
	}
	return seal, &Opener{client: unwrap, mount: mount, key: key, reference: mount + "/" + key}, nil
}

// ContextDeletionSigningKey signs through the audit-wrap lifetime with the
// profile's context deletion signing key (ADR-205 decision 6) at the pinned
// version, and accepts only signatures that verify under the pinned public
// key. Its client reaches only <mount>/sign/<key>: it cannot create, rotate,
// read or export a key. It refuses the configuration audit key, malformed
// names and any key the profile did not select (the recipe already keeps that
// key apart from both audit keys). Every call borrows audit-wrap's current
// token; the caller closes the key.
func (s *InstalledConfigurationProviderEffects) ContextDeletionSigningKey(mount, key string, version int, public ed25519.PublicKey) (*SigningKey, error) {
	if s == nil || s.effects == nil || s.effects.wrap == nil || !keyName.MatchString(mount) || !keyName.MatchString(key) ||
		version < 1 || version > 2147483647 || len(public) != ed25519.PublicKeySize ||
		mount == s.input.AuditMount && key == s.input.AuditKey ||
		s.input.ContextDeletionSigning != (contracts.OwnerPublicTransit{Mount: mount, Key: key}) {
		return nil, ErrKeyService
	}
	sign, err := newOwnerProviderEffectClient(s.effects.wrap, mount+"/sign/"+key)
	if err != nil {
		return nil, err
	}
	return &SigningKey{client: sign, mount: mount, name: key, version: version, public: bytes.Clone(public)}, nil
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
	b, err := mounts.Read(ctx, s.files, s.input.TokenFile, 16<<10)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, ErrKeyService
	}
	return b, nil
}

// recoveryCurrent is one committed read-only recovery observation. No SQL
// lock is retained across provider HTTP or credential effects.
func (s *InstalledConfigurationProviderEffects) recoveryCurrent(ctx context.Context) (fleet.RecoveryState, error) {
	r, err := s.recovery.RecoveryState(ctx)
	if err != nil || !r.Valid(time.Now()) || r.InstallationID != s.input.InstallationID {
		return fleet.RecoveryState{}, ErrKeyService
	}
	return r, nil
}

// auditCredential reads the mounted audit object-store credential.
func (s *InstalledConfigurationProviderEffects) auditCredential(ctx context.Context) (contracts.OwnerStorageCredential, error) {
	b, err := mounts.Read(ctx, s.files, s.input.AuditCredentialFile, 32<<10)
	if err != nil {
		return contracts.OwnerStorageCredential{}, ErrKeyService
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil {
		return contracts.OwnerStorageCredential{}, ErrKeyService
	}
	return c, nil
}

// currentMaterial brackets the mounted credential read with two recovery
// observations of the same revision; the earlier freshness bounds its use.
func (s *InstalledConfigurationProviderEffects) currentMaterial(ctx context.Context) (contracts.OwnerStorageCredential, time.Time, error) {
	var zero contracts.OwnerStorageCredential
	if s == nil || ctx == nil || ctx.Err() != nil || s.root.Err() != nil {
		return zero, time.Time{}, ErrKeyService
	}
	first, err := s.recoveryCurrent(ctx)
	if err != nil {
		return zero, time.Time{}, err
	}
	call, end := context.WithDeadline(ctx, first.FreshUntil)
	defer end()
	credential, err := s.auditCredential(call)
	if err != nil {
		return zero, time.Time{}, err
	}
	last, err := s.recoveryCurrent(call)
	until := identity.Earlier(first.FreshUntil, last.FreshUntil)
	if err != nil || !configurationProviderSameRecovery(first, last, time.Now()) || call.Err() != nil || !time.Now().Before(until) {
		return zero, time.Time{}, ErrKeyService
	}
	return credential, until, nil
}
func (s *InstalledConfigurationProviderEffects) current(ctx context.Context) (time.Time, error) {
	_, until, err := s.currentMaterial(ctx)
	return until, err
}

// ReadAuditCredentials reads the mounted audit credential under a current
// recovery observation.
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
