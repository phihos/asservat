package feasibility

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/klauspost/compress/zstd"
	"io"
	"math/rand/v2"
	"os"
	"testing"
	"time"
)

type countedReader struct {
	io.Reader
	N int64
}

func (c *countedReader) Read(p []byte) (int, error) {
	n, e := c.Reader.Read(p)
	c.N += int64(n)
	return n, e
}
func TestSequentialBaseline(t *testing.T) {
	if os.Getenv("ASSERVAT_BASELINE") != "1" {
		t.Skip("explicit sequential comparison")
	}
	s := setup(t)
	a, e := primitive()
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "sequential-cipher")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	defer os.Remove(f.Name())
	w, e := a.NewEncryptingWriter(f, []byte("sequential-synthetic"))
	if e != nil {
		t.Fatal(e)
	}
	z, e := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.CopyN(z, rand.NewChaCha8([32]byte{42}), 64*MiB); e != nil {
		t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	info, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	tag, e := s.multipart(context.Background(), "sequential", f)
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	r, e := s.Client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &s.Bucket, Key: aws.String("sequential"), IfMatch: &tag})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	count := &countedReader{Reader: r.Body}
	d, e := a.NewDecryptingReader(count, []byte("sequential-synthetic"))
	if e != nil {
		t.Fatal(e)
	}
	unzip, e := zstd.NewReader(d, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64*MiB))
	if e != nil {
		t.Fatal(e)
	}
	defer unzip.Close()
	if _, e = io.CopyN(io.Discard, unzip, 49*MiB); e != nil {
		t.Fatal(e)
	}
	if _, e = io.CopyN(io.Discard, unzip, MiB); e != nil {
		t.Fatal(e)
	}
	data, _ := json.MarshalIndent(map[string]any{"nativeBytes": 64 * MiB, "cipherBytes": info.Size(), "requestedRangeBytes": MiB, "nativeOffset": 49 * MiB, "ciphertextRead": count.N, "rangeMilliseconds": float64(time.Since(start).Microseconds()) / 1000, "limitation": "Separate seeded incompressible stream; sequential read/discard work measurement, not resumed whole-file integrity proof"}, "", "  ")
	p := os.Getenv("ASSERVAT_BASELINE_REPORT")
	if p == "" {
		t.Fatal("baseline output path required")
	}
	if e = os.WriteFile(p, append(data, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
