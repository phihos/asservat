package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/privacy"
)

const nativeMixedOld = "eed8594020645fe6d10f8c6565e69a6235c7507d"
const nativeMixedNew = "fa69b01948edf9d7baf1f00453e1482a224fd4ea"

type nativeVersionInput struct {
	Action                         string
	Postgres                       string
	SQLRoots                       []byte
	SQLServerName                  string
	SQLMinimumVersion              uint16
	Root, Installation             string
	TopologySource                 privacy.PolicySourceRef
	Profile                        value.DownloadWorkerProfile
	Enrollment                     value.WorkerEnrollment
	Authority                      artifact.DownloadAuthority
	Operation                      value.NativeOperation
	Peer                           value.KeyPeer
	Endpoint                       string
	Roots, Certificate, PrivateKey []byte
	Hello                          contracts.NativeHello
	Worker                         value.WorkerCredentialTarget
	WorkerKey                      artifact.Digest
	Source                         evidence.NativeContextSource
	Warmup                         *value.NativeOperation
	BodyBytes                      int
	Lease                          value.NativeLease
	Delivery                       artifact.DownloadDeliveryLease
	Command                        contracts.NativeCommand
	ExpectedPeer                   artifact.Digest
	ServerCertificate, ServerKey   []byte
}
type nativeVersionOutput struct {
	Format, ProductionRevision, Stage, ErrorClass          string
	CompiledSchema                                         int64
	Accepted, HasRenewer                                   bool
	OperationSHA256                                        string
	Sequence                                               int64
	Until                                                  time.Time
	NativeState                                            contracts.NativeConversationState
	ReaderCalls, DataFrames, DataBytes                     int64
	ConstructionStage, ConstructionClass, ConstructionStep string
	AuthenticatedRequests, UpstreamOpens                   int64
	DeliveredBytes, AcknowledgedChunks                     int64
}

type nativeVersionBinary struct {
	Path         string  `json:"path"`
	Revision     string  `json:"production_revision"`
	Tree         string  `json:"production_tree"`
	SHA256       string  `json:"sha256"`
	BuildSeconds float64 `json:"build_seconds"`
}
type nativeVersionManifest struct {
	Format        string                         `json:"format"`
	FixtureSHA256 string                         `json:"fixture_sha256"`
	GoVersion     string                         `json:"go_version"`
	Binaries      map[string]nativeVersionBinary `json:"binaries"`
}

func nativeVersionManifestFor(t *testing.T) nativeVersionManifest {
	t.Helper()
	path := os.Getenv("ASSERVAT_NATIVE_VERSION_HELPERS")
	if path == "" {
		t.Skip("build pinned old/new native-version helpers and set ASSERVAT_NATIVE_VERSION_HELPERS")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("version-helper manifest unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		t.Fatal("version-helper manifest exceeds bound")
	}
	var manifest nativeVersionManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Format != "native-version-build/v1" || len(manifest.Binaries) != 2 {
		t.Fatal("invalid version-helper manifest")
	}
	source, err := os.ReadFile(filepath.Join("..", "fixtures", "native-version-helper", "main.go"))
	if err != nil {
		t.Fatal("fixture source unavailable")
	}
	sum := sha256.Sum256(source)
	if manifest.FixtureSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("version helpers were built from another test fixture")
	}
	for name, revision := range map[string]string{"old": nativeMixedOld, "new": nativeMixedNew} {
		binary, ok := manifest.Binaries[name]
		if !ok || binary.Revision != revision || len(binary.Tree) != 40 || binary.BuildSeconds <= 0 {
			t.Fatal("helper production provenance mismatch", name)
		}
		file, err := os.Open(binary.Path)
		if err != nil {
			t.Fatal("helper unavailable", name)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
			file.Close()
			t.Fatal("invalid helper executable", name)
		}
		hash := sha256.New()
		_, err = io.Copy(hash, io.LimitReader(file, 256<<20))
		file.Close()
		if err != nil || hex.EncodeToString(hash.Sum(nil)) != binary.SHA256 {
			t.Fatal("helper executable changed", name)
		}
		t.Logf("actual %s production=%s tree=%s binarySHA256=%s buildSeconds=%.3f fixtureSHA256=%s", name, binary.Revision, binary.Tree, binary.SHA256, binary.BuildSeconds, manifest.FixtureSHA256)
	}
	return manifest
}

type nativeVersionBoundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *nativeVersionBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 4096 - b.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:max(remaining, 0)]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
func invokeNativeVersion(ctx context.Context, binary nativeVersionBinary, in nativeVersionInput, files ...*os.File) (nativeVersionOutput, error) {
	var out nativeVersionOutput
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > 256<<10 {
		return out, errors.New("helper input exceeds bound")
	}
	defer clear(raw)
	call, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(call, binary.Path)
	command.Stdin = bytes.NewReader(raw)
	command.ExtraFiles = files
	var stdout nativeVersionBoundedOutput
	command.Stdout, command.Stderr = &stdout, io.Discard
	command.WaitDelay = time.Second
	err = command.Run()
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if stdout.overflow || decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.Format != "native-version-helper/v1" || out.ProductionRevision != binary.Revision || out.CompiledSchema != 100 {
		return out, errors.New("helper result/provenance invalid")
	}
	if err != nil {
		return out, fmt.Errorf("helper did not complete action=%s stage=%s class=%s", in.Action, out.Stage, out.ErrorClass)
	}
	return out, nil
}
func runNativeVersion(t *testing.T, ctx context.Context, binary nativeVersionBinary, in nativeVersionInput) nativeVersionOutput {
	t.Helper()
	started := time.Now()
	out, err := invokeNativeVersion(ctx, binary, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("version=%s action=%s stage=%s accepted=%t class=%s elapsed=%s sequence=%d operationSHA256=%s leaseUntil=%s readerCalls=%d dataFrames=%d dataBytes=%d", binary.Revision[:8], in.Action, out.Stage, out.Accepted, out.ErrorClass, time.Since(started), out.Sequence, out.OperationSHA256, out.Until.UTC().Format(time.RFC3339Nano), out.ReaderCalls, out.DataFrames, out.DataBytes)
	return out
}
