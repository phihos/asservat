//go:build ignore

// Synthetic native Go heap fixture generation in an explicitly owned process.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/google/pprof/profile"
)

var retained [][]byte

//go:noinline
func branchA(bits, depth int) {
	if depth == 0 {
		retained = append(retained, make([]byte, 64))
		return
	}
	if bits&1 == 0 {
		branchA(bits>>1, depth-1)
	} else {
		branchB(bits>>1, depth-1)
	}
}

//go:noinline
func branchB(bits, depth int) {
	if depth == 0 {
		retained = append(retained, make([]byte, 64))
		return
	}
	if bits&1 == 0 {
		branchA(bits>>1, depth-1)
	} else {
		branchB(bits>>1, depth-1)
	}
}
func main() {
	output := flag.String("output", "", "synthetic gzip heap fixture destination")
	count := flag.Int("buckets", 40000, "distinct retained allocation stacks (1..65536)")
	flag.Parse()
	if *output == "" || *count < 1 || *count > 65536 {
		panic("bounded output/count required")
	}
	retained = make([][]byte, 0, *count)
	runtime.MemProfileRate = 1
	for i := 0; i < *count; i++ {
		branchA(i, 16)
	}
	runtime.GC()
	runtime.GC()
	var b bytes.Buffer
	if err := pprof.WriteHeapProfile(&b); err != nil {
		panic(err)
	}
	runtime.KeepAlive(retained)
	p, err := profile.ParseData(b.Bytes())
	if err != nil {
		panic(err)
	}
	labels, bytesLabels, refs := 0, 0, 0
	for _, s := range p.Sample {
		for _, v := range s.Label {
			labels += len(v)
		}
		for key, v := range s.NumLabel {
			labels += len(v)
			if key == "bytes" {
				bytesLabels += len(v)
			}
		}
		refs += len(s.Location)
	}
	gz, err := gzip.NewReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		panic(err)
	}
	decompressed, err := io.Copy(io.Discard, gz)
	if err != nil {
		panic(err)
	}
	if err = gz.Close(); err != nil {
		panic(err)
	}
	if err = os.WriteFile(*output, b.Bytes(), 0600); err != nil {
		panic(err)
	}
	hash := sha256.Sum256(b.Bytes())
	report := map[string]any{"requestedBuckets": *count, "samples": len(p.Sample), "locations": len(p.Location), "functions": len(p.Function), "labels": labels, "bytesLabels": bytesLabels, "locationReferences": refs, "nativeBytes": b.Len(), "decompressedBytes": decompressed, "sha256": hex.EncodeToString(hash[:]), "goVersion": runtime.Version(), "sampleTypes": p.SampleType}
	if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
		panic(err)
	}
}
