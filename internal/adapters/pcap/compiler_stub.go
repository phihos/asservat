//go:build !(cgo && libpcap)

// Package pcap compiles pcap-filter expressions with libpcap on the hub (S2,
// ADR-243). Only the hub build links libpcap (build tag libpcap, static
// archive); every other build, including the cgo-free product binary, gets
// this stub, and previews with a filter report FilterCompilerUnavailable.
package pcap

import value "asservat.local/asservat/internal/domain/planning"

type Compiler struct{}

func NewCompiler() *Compiler { return &Compiler{} }

func (c *Compiler) Version() string { return "" }

func (c *Compiler) CompileFilter(string) (value.CompiledFilter, error) {
	return value.CompiledFilter{}, value.ErrFilterCompilerUnavailable
}
