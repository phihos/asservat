// Package bootstrap owns concrete runtime wiring and role-scoped inputs.
package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"context"
	"encoding/hex"
	"flag"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type WorkerStartup struct {
	Target        value.WorkerCredentialTarget
	ClusterID     string
	ControlDigest artifact.Digest
}

// Arguments come only from the protected dispatch template. Fixed mount paths
// cannot be redirected through the CLI or a public download request.
func ParseWorkerStartup(args []string, podUID string) (WorkerStartup, error) {
	var out WorkerStartup
	var created, until, digest, control, token string
	set := flag.NewFlagSet("download-worker", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&out.Target.InstallationID, "installation", "", "")
	set.StringVar(&out.ClusterID, "cluster", "", "")
	set.StringVar(&out.Target.WorkerID, "dispatch", "", "")
	set.StringVar(&out.Target.SessionID, "session", "", "")
	set.StringVar(&out.Target.QueryID, "query", "", "")
	set.StringVar(&created, "created-at", "", "")
	set.StringVar(&until, "until", "", "")
	set.StringVar(&digest, "control-sha256", "", "")
	set.StringVar(&control, "control", "", "")
	set.StringVar(&token, "token", "", "")
	// Reject duplicates and alternative flag spellings, not just last-value-wins.
	if len(args) != 18 {
		return out, artifact.ErrInvalid
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i += 2 {
		if seen[args[i]] || len(args[i]) < 3 || args[i][:2] != "--" {
			return out, artifact.ErrInvalid
		}
		seen[args[i]] = true
	}
	if set.Parse(args) != nil || set.NArg() != 0 || control != contracts.WorkerControlPath || token != contracts.WorkerTokenPath {
		return out, artifact.ErrInvalid
	}
	var err error
	out.Target.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil || created != out.Target.CreatedAt.UTC().Format(time.RFC3339Nano) {
		return out, artifact.ErrInvalid
	}
	out.Target.RunUntil, err = time.Parse(time.RFC3339Nano, until)
	if err != nil || until != out.Target.RunUntil.UTC().Format(time.RFC3339Nano) {
		return out, artifact.ErrInvalid
	}
	b, err := hex.DecodeString(digest)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != digest {
		return out, artifact.ErrInvalid
	}
	copy(out.ControlDigest[:], b)
	out.Target.PodUID = podUID
	if !out.Target.Valid() || !value.UUID(out.ClusterID) || out.ControlDigest == (artifact.Digest{}) {
		return out, artifact.ErrInvalid
	}
	return out, nil
}

func LoadWorkerTrust(input WorkerStartup, raw []byte, now time.Time) (*mtls.WorkerControlTrust, error) {
	if !input.Target.Valid() || !value.UUID(input.ClusterID) || len(raw) > contracts.WorkerControlMaxBytes {
		return nil, artifact.ErrInvalid
	}
	d, err := mtls.WorkerControlDigest(map[string]string{"worker.json": string(raw)})
	if err != nil || d != input.ControlDigest {
		return nil, artifact.ErrInvalid
	}
	trust, err := mtls.ParseWorkerControl(raw)
	if err != nil || trust.InstallationID != input.Target.InstallationID || trust.ClusterID != input.ClusterID {
		return nil, artifact.ErrInvalid
	}
	if _, _, err = trust.Roots(now); err != nil {
		return nil, err
	}
	return trust, nil
}

func waitWorker(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return artifact.ErrDownloadExpired
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RunDownloadWorker preserves credential-only v1 and explicitly composes the
// regional native loop for accepted v2 inputs. Identity readiness never reports
// a successful artifact download; each native operation has separate authority.
func RunDownloadWorker(ctx context.Context, args []string, podUID string, status io.Writer) error {
	input, err := ParseWorkerStartup(args, podUID)
	if err != nil || ctx == nil || status == nil {
		return artifact.ErrInvalid
	}
	if err = disableWorkerCoreDumps(); err != nil {
		return artifact.ErrDownloadUnavailable
	}
	root, err := os.OpenRoot(filepath.Dir(contracts.WorkerControlPath))
	if err != nil {
		return artifact.ErrDownloadUnavailable
	}
	defer root.Close()
	raw, err := mounts.Read(ctx, root, filepath.Base(contracts.WorkerControlPath), contracts.WorkerControlMaxBytes)
	if err != nil {
		return artifact.ErrDownloadUnavailable
	}
	trust, err := LoadWorkerTrust(input, raw, time.Now())
	if err != nil {
		return err
	}
	server, issuer, err := trust.Roots(time.Now())
	if err != nil {
		return err
	}
	var nativeCredentials contracts.WorkerStoreCredentials
	if trust.Native() != nil {
		nativeCredentials, err = loadWorkerNativeCredentials(ctx, input.Target.RunUntil)
		if err != nil {
			return err
		}
	}
	client, err := mtls.NewWorkerCredentialsVia(trust.Endpoint, trust.Address, input.Target, server, issuer, mtls.NewProjectedWorkerToken(), time.Now)
	if err != nil {
		return err
	}
	ready := make(chan value.KeyPeer, 1)
	statusCtx, stopStatus := context.WithCancel(ctx)
	defer stopStatus()
	// One process-owned reporter. A blocked stdout cannot stall renewal or
	// Close; process exit also terminates a blocked write. Never spawn per event.
	supervisor := evidence.WorkerCredentialSupervisor{Client: client, Target: input.Target, Now: time.Now, Wait: waitWorker, Jitter: func() time.Duration { return time.Duration(rand.Int64N(int64(500 * time.Millisecond))) }, IdentityReady: ready}
	if native := trust.Native(); native != nil {
		report := make(chan value.KeyPeer, 1)
		go reportWorkerMessage(statusCtx, report, status, "worker credentials established\n")
		return runWorkerNativePair(ctx, ready, supervisor.Run, func(work context.Context) error {
			select {
			case report <- value.KeyPeer{}:
			default:
			}
			return runWorkerNative(work, input, native, client, nativeCredentials)
		})
	}
	go reportWorkerStatus(statusCtx, ready, status)
	return supervisor.Run(ctx)
}

func reportWorkerStatus(ctx context.Context, ready <-chan value.KeyPeer, status io.Writer) {
	reportWorkerMessage(ctx, ready, status, "worker credentials established; native transfer unavailable\n")
}

func reportWorkerMessage(ctx context.Context, ready <-chan value.KeyPeer, status io.Writer, message string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ready:
			if ctx.Err() != nil {
				return
			}
			_, _ = io.WriteString(status, message)
		}
	}
}
