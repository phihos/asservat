package bootstrap

import (
	"asservat.local/asservat/internal/adapters/packets"
	analysisapp "asservat.local/asservat/internal/application/analysis"
	planningapp "asservat.local/asservat/internal/application/planning"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	planning "asservat.local/asservat/internal/domain/planning"
	"context"
	"errors"
	"strings"
)

type publicPacketQueryCompiler struct{ inner planningapp.FilterCompiler }

var _ analysisapp.PacketQueryCompiler = publicPacketQueryCompiler{}

func (c publicPacketQueryCompiler) CompilePacketQueryFilter(ctx context.Context, expression string) (query.PacketQueryProgram, error) {
	if ctx == nil || ctx.Err() != nil || len(expression) > 512 || planningapp.RawBytePredicate(expression) {
		return query.PacketQueryProgram{}, query.ErrInvalid
	}
	expression = planningapp.NormalizeFilter(expression)
	if expression == "" {
		return query.PacketQueryProgram{}, nil
	}
	if c.inner == nil || planningapp.ScreenFilter("packet_filter", expression) != nil {
		return query.PacketQueryProgram{}, query.ErrInvalid
	}
	version, ok := c.inner.(interface{ Version() string })
	if !ok || !strings.HasPrefix(version.Version(), "libpcap version 1.11.0") {
		return query.PacketQueryProgram{}, query.ErrUnavailable
	}
	p, e := c.inner.CompileFilter(expression)
	if ctx.Err() != nil {
		return query.PacketQueryProgram{}, query.ErrUnavailable
	}
	if e != nil {
		if errors.Is(e, planning.ErrFilterCompilerUnavailable) {
			return query.PacketQueryProgram{}, query.ErrUnavailable
		}
		return query.PacketQueryProgram{}, query.ErrInvalid
	}
	if len(p.Program) < 1 || p.LinkType != planning.FilterLinkType || p.Snaplen != planning.FilterSnaplen || packets.CheckProgram(p.Program) != nil {
		return query.PacketQueryProgram{}, query.ErrInvalid
	}
	out := query.PacketQueryProgram{CompilerDigest: query.PacketQueryCompilerDigest(), Instructions: make([]artifact.FilterInstruction, len(p.Program))}
	for i, v := range p.Program {
		out.Instructions[i] = artifact.FilterInstruction{Code: v.Code, Jt: v.Jt, Jf: v.Jf, K: v.K}
	}
	out.ProgramDigest = query.PacketQueryProgramDigest(out.Instructions)
	if !out.Valid() {
		return query.PacketQueryProgram{}, query.ErrInvalid
	}
	return out, nil
}
