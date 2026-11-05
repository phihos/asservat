package bootstrap

import (
	planning "asservat.local/asservat/internal/domain/planning"
	"context"
	"testing"
)

type packetFilterCompilerFixture struct {
	calls int
	hook  func()
}

func (c *packetFilterCompilerFixture) Version() string { return "libpcap version 1.11.0" }
func (c *packetFilterCompilerFixture) CompileFilter(string) (planning.CompiledFilter, error) {
	c.calls++
	if c.hook != nil {
		c.hook()
	}
	return planning.CompiledFilter{LinkType: planning.FilterLinkType, Snaplen: planning.FilterSnaplen, Program: []planning.BPFInstruction{{Code: 6, K: 65535}}}, nil
}
func TestPacketQueryCompilerScreensBeforeEffectAndKeepsCancellation(t *testing.T) {
	for _, expr := range []string{"tcp[13] & 2 != 0", "host secret.example", "tcp; cat /file"} {
		c := &packetFilterCompilerFixture{}
		if _, e := (publicPacketQueryCompiler{c}).CompilePacketQueryFilter(t.Context(), expr); e == nil || c.calls != 0 {
			t.Fatal("invalidreachedcompiler", expr, e)
		}
	}
	c := &packetFilterCompilerFixture{}
	p, e := (publicPacketQueryCompiler{c}).CompilePacketQueryFilter(t.Context(), " tcp port 80 ")
	if e != nil || !p.Valid() || len(p.Instructions) != 1 || c.calls != 1 {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	c.hook = cancel
	if _, e = (publicPacketQueryCompiler{c}).CompilePacketQueryFilter(ctx, "tcp port 80"); e == nil {
		t.Fatal("latecompilerreturnedprogram")
	}
}
