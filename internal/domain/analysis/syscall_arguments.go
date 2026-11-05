package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	SyscallQueryPageBytes   = ContextResultBytes - 4096
	SyscallQueryReadBatches = 2
	SyscallQueryQueryUnits  = 4
	SyscallQueryWorkerBytes = SyscallProjectionWorkerBytes
)

// RawSyscallQueryRequest contains display selection only. Missing GrantID is
// permitted for discovery; it never makes an admitted scope or authority valid.
type RawSyscallQueryRequest struct {
	CaseID, ArtifactID, GrantID, IdempotencyKey string
	Selection                                   SyscallWindow
}

func (r RawSyscallQueryRequest) Valid() bool {
	return authorization.UUID(r.CaseID) && authorization.UUID(r.ArtifactID) && (r.GrantID == "" || authorization.UUID(r.GrantID)) && len(r.IdempotencyKey) >= 1 && len(r.IdempotencyKey) <= 128 && r.Selection.Valid() && r.Selection.View == SyscallQueryView
}

// SyscallArgumentPage retains whole events in matching native order. Counts
// describe the entire authenticated source and do not assert acquisition loss.
type SyscallArgumentPage struct {
	Version              artifact.Digest
	Start, TotalMatching int
	Events               []artifact.RawArgumentEvent
	SyscallRecordCounts
}

func (p SyscallArgumentPage) ValidShape(s SyscallSelection, version artifact.Digest, pod string) bool {
	if p.Version != version || !s.Matches(version) || s.View != SyscallQueryView || !p.SyscallRecordCounts.Valid() || p.Events == nil || p.Start != s.Start || p.TotalMatching < 0 || uint64(p.TotalMatching) > p.RecordCount || p.Start > p.TotalMatching || len(p.Events) > s.Limit || len(p.Events) > p.TotalMatching-p.Start || len(p.Events) == 0 && (p.Start != 0 || p.TotalMatching != 0) {
		return false
	}
	for _, e := range p.Events {
		if !e.WellFormed() || e.Identity.PodUID != pod || !s.Includes(e.Syscall, e.Outcome) {
			return false
		}
	}
	return p.EncodedSize() <= SyscallQueryPageBytes
}
func (p SyscallArgumentPage) Valid(s SyscallSelection, version artifact.Digest, pod string, from, until time.Time) bool {
	if !p.ValidShape(s, version, pod) {
		return false
	}
	for _, e := range p.Events {
		if !e.Valid(pod, from, until) {
			return false
		}
	}
	return true
}
func (p SyscallArgumentPage) Next(s SyscallSelection, version artifact.Digest) string {
	next := p.Start + len(p.Events)
	if !s.Matches(version) || p.Version != version || p.Start != s.Start || len(p.Events) == 0 || next >= p.TotalMatching {
		return ""
	}
	return s.Cursor(next, version)
}
func CloneSyscallArgumentPage(p SyscallArgumentPage) SyscallArgumentPage {
	if p.Events != nil {
		p.Events = append([]artifact.RawArgumentEvent{}, p.Events...)
		for i := range p.Events {
			if p.Events[i].Arguments != nil {
				p.Events[i].Arguments = append([]artifact.ArgumentValue{}, p.Events[i].Arguments...)
			}
			if p.Events[i].DurationNS != nil {
				n := *p.Events[i].DurationNS
				p.Events[i].DurationNS = &n
			}
		}
	}
	return p
}
func (p *SyscallArgumentPage) Clear() {
	for i := range p.Events {
		clear(p.Events[i].Arguments)
		p.Events[i] = artifact.RawArgumentEvent{}
	}
	clear(p.Events)
	*p = SyscallArgumentPage{}
}

// EncodedSize is the exact default Go JSON size of this private page. It
// includes escaping and all fixed fields; native/public codecs bound their
// own complete wrappers independently.
func (p SyscallArgumentPage) EncodedSize() int {
	n := len(`{"Version":[],"Start":,"TotalMatching":,"Events":[],"RecordCount":,"UnmatchedEvents":,"UnfinishedEvents":,"UnknownEvents":}`)
	if p.Events == nil {
		n += 2
	}
	for i, v := range p.Version {
		if i > 0 {
			n++
		}
		n += len(strconv.FormatUint(uint64(v), 10))
	}
	n += len(strconv.Itoa(p.Start)) + len(strconv.Itoa(p.TotalMatching))
	for _, v := range []uint64{p.RecordCount, p.UnmatchedEvents, p.UnfinishedEvents, p.UnknownEvents} {
		n += len(strconv.FormatUint(v, 10))
	}
	for i, e := range p.Events {
		if i > 0 {
			n++
		}
		n += rawSyscallEventSize(e)
	}
	return n
}
func rawSyscallEventSize(e artifact.RawArgumentEvent) int {
	n := len(`{"identity":{"process_ref":,"thread_ref":,"pod_uid":},"syscall":,"abi":,"timestamp":,"outcome":,"arguments":[]}`)
	if e.Arguments == nil {
		n += 2
	}
	for _, v := range []string{e.Identity.ProcessRef, e.Identity.ThreadRef, e.Identity.PodUID, e.Syscall, e.ABI, e.Timestamp, e.Outcome} {
		n += rawJSONStringSize(v)
	}
	if e.DurationNS != nil {
		n += len(`,"duration_ns":`) + len(strconv.FormatUint(*e.DurationNS, 10))
	}
	if e.Errno != "" {
		n += len(`,"errno":`) + rawJSONStringSize(e.Errno)
	}
	for i, a := range e.Arguments {
		if i > 0 {
			n++
		}
		n += len(`{"name":,"value":,"truncated":}`) + rawJSONStringSize(a.Name) + rawJSONStringSize(a.Value)
		if a.Truncated {
			n += 4
		} else {
			n += 5
		}
	}
	return n
}
func rawJSONStringSize(s string) int {
	n := 2
	for _, r := range s {
		switch {
		case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
			n += 2
		case r < 0x20 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
			n += 6
		default:
			n += utf8.RuneLen(r)
		}
	}
	return n
}
