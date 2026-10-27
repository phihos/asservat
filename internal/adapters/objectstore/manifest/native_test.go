package manifest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// recorderFixture is a synthetic ongoing PCAPNG save of a 64 MiB artifact.
func recorderFixture(t *testing.T) (*Validator, artifact.ContextExpectation, artifact.Layout, artifact.Copies, []byte) {
	t.Helper()
	v, e, l, c, _ := fixture(t)
	t0 := e.TriggeredAt.Add(40 * time.Second)
	e.NativeType = artifact.PCAPNGArtifact
	e.ActionID = "a0123456789abcdef01234567"
	e.TriggeredAt = t0
	e.Registration.NativeLimit = 64 << 20
	e.Lifecycle = &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: testID(30), SourceStartedAt: t0.Add(-35 * time.Second), SnapshotID: testID(31), RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"}
	l.Binding = e.Binding()
	b, err := v.MarshalContext(e, l, c, t0.Add(-30*time.Second), t0.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return v, e, l, c, b
}

func TestRecorderManifestBindsTypeAndOngoingProvenance(t *testing.T) {
	v, e, _, c, b := recorderFixture(t)
	m, err := v.ParseContext(b, e, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kind":"packetCapture"`, `"mediaType":"application/x-pcapng"`, `"format":"pcapng"`, `"evidenceType":"packetCapture"`, `"executionMode":"ongoing"`, `"requestedBefore":"30s"`, `"after":"10s"`, `"gapReasons":[]`, `"windowCoverage":"full"`, `"snapshotID":"` + testID(31) + `"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatal("manifest lacks", want, string(b))
		}
	}
	if bytes.Contains(b, []byte("projectionDigest")) || !m.StartedAt.Before(e.TriggeredAt) {
		t.Fatal("recorder manifest projection/prehistory")
	}
	cases := map[string]func(map[string]any){
		"kind":             func(m map[string]any) { m["kind"] = "kubernetesSnapshot" },
		"media type":       func(m map[string]any) { m["mediaType"] = "application/json" },
		"format":           func(m map[string]any) { m["format"] = artifact.ContextFormat },
		"evidence type":    func(m map[string]any) { obj(m, "privacy")["evidenceType"] = "context" },
		"snapshot":         func(m map[string]any) { obj(m, "actionLifecycle")["snapshotID"] = testID(40) },
		"source session":   func(m map[string]any) { obj(m, "actionLifecycle")["sourceSessionID"] = testID(40) },
		"window coverage":  func(m map[string]any) { obj(m, "actionLifecycle")["windowCoverage"] = "partial" },
		"history coverage": func(m map[string]any) { obj(m, "actionLifecycle")["historyCoverage"] = "partial" },
		"invented stop":    func(m map[string]any) { obj(m, "actionLifecycle")["sourceStoppedAt"] = "2026-10-09T12:00:41Z" },
		"before":           func(m map[string]any) { obj(m, "actionLifecycle")["requestedBefore"] = "60s" },
		"trigger kind":     func(m map[string]any) { obj(m, "actionLifecycle")["triggerKind"] = "manual" },
		"onTrigger claim": func(m map[string]any) {
			l := obj(m, "actionLifecycle")
			for _, k := range []string{"sourceSessionID", "sourceStartedAt", "snapshotID", "requestedBefore", "after", "historyCoverage", "gapReasons", "windowCoverage"} {
				delete(l, k)
			}
			l["executionMode"] = "onTrigger"
		},
		"completeness":   func(m map[string]any) { obj(m, "completeness")["source"] = "partial" },
		"gap invented":   func(m map[string]any) { obj(m, "actionLifecycle")["gapReasons"] = []any{"warming"} },
		"t0 moved":       func(m map[string]any) { obj(m, "actionLifecycle")["triggeredAt"] = "2026-10-09T12:00:30Z" },
		"pod projection": func(m map[string]any) { obj(m, "provenance")["projectionDigest"] = strings.Repeat("ab", 32) },
	}
	for name, change := range cases {
		if _, err := v.ParseContext(mutate(t, b, change), e, c); err == nil {
			t.Fatal("accepted changed recorder manifest:", name)
		}
	}
	// A partial window reports its gaps as partial source completeness.
	partial := e
	partial.Lifecycle = e.Lifecycle.Clone()
	partial.Lifecycle.SourceStoppedAt, partial.Lifecycle.WindowCoverage, partial.Lifecycle.GapReasons = e.TriggeredAt.Add(2*time.Second), "partial", []string{"targetGone"}
	_, _, l, _, _ := recorderFixture(t)
	pb, err := v.MarshalContext(partial, l, c, e.TriggeredAt.Add(-30*time.Second), e.TriggeredAt.Add(2*time.Second))
	if err != nil || !bytes.Contains(pb, []byte(`"source":"partial"`)) || !bytes.Contains(pb, []byte(`"gaps":["targetGone"]`)) || !bytes.Contains(pb, []byte(`"sourceStoppedAt":"2026-10-09T12:00:42Z"`)) {
		t.Fatal("partial window provenance", err, string(pb))
	}
	// Records cannot predate the source, and recorder types are bounded.
	if _, err = v.MarshalContext(e, l, c, e.Lifecycle.SourceStartedAt.Add(-time.Second), e.TriggeredAt); err == nil {
		t.Fatal("acquisition before the source started accepted")
	}
	save := e
	save.Lifecycle = e.Lifecycle.Clone()
	save.Lifecycle.TriggerKind, save.Lifecycle.After, save.Lifecycle.Origin = "recordingSave", 0, &artifact.RecordingSaveOrigin{PolicyUID: "policy-uid", PolicyExecutionDigest: artifact.Digest{5}}
	sb, err := v.MarshalContext(save, l, c, e.TriggeredAt.Add(-30*time.Second), e.TriggeredAt)
	if err != nil || !bytes.Contains(sb, []byte(`"recordingSaveOrigin":{"policyUID":"policy-uid"`)) || !bytes.Contains(sb, []byte(`"after":"0s"`)) {
		t.Fatal("recording save origin", err)
	}
}

func pcapngBlock(order binary.ByteOrder, typ uint32, body []byte) []byte {
	n := 12 + len(body)
	b := make([]byte, n)
	order.PutUint32(b, typ)
	order.PutUint32(b[4:], uint32(n))
	copy(b[8:], body)
	order.PutUint32(b[n-4:], uint32(n))
	return b
}
func shb(order binary.ByteOrder) []byte {
	body := make([]byte, 16)
	order.PutUint32(body, 0x1A2B3C4D)
	order.PutUint16(body[4:], 1)
	order.PutUint64(body[8:], ^uint64(0))
	return pcapngBlock(order, pcapngSHB, body)
}
func idb(order binary.ByteOrder, snap uint32) []byte {
	body := make([]byte, 8)
	order.PutUint16(body, 1)
	order.PutUint32(body[4:], snap)
	return pcapngBlock(order, pcapngIDB, body)
}
func epb(order binary.ByteOrder, iface, captured, original uint32) []byte {
	body := make([]byte, 20+(captured+3)/4*4)
	order.PutUint32(body, iface)
	order.PutUint32(body[12:], captured)
	order.PutUint32(body[16:], original)
	return pcapngBlock(order, pcapngEPB, body)
}

func runCheck(t *testing.T, c NativeCheck, b []byte, step int) error {
	t.Helper()
	for len(b) > 0 {
		n := min(step, len(b))
		if err := c.Write(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return c.Close()
}

func TestPCAPNGStructureCheck(t *testing.T) {
	v, e, _, _, _ := recorderFixture(t)
	le, be := binary.LittleEndian, binary.BigEndian
	valid := bytes.Join([][]byte{shb(le), idb(le, 128), epb(le, 0, 54, 1500), epb(le, 0, 96, 96), pcapngBlock(le, pcapngISB, make([]byte, 12)), shb(be), idb(be, 0), epb(be, 0, 1000, 1000)}, nil)
	for _, step := range []int{1, 7, 4096, len(valid)} {
		c, err := v.NativeCheck(e, ContextManifest{})
		if err != nil {
			t.Fatal(err)
		}
		if err = runCheck(t, c, valid, step); err != nil {
			t.Fatal("valid PCAPNG", step, err)
		}
	}
	nrb := pcapngBlock(le, 4, make([]byte, 4))
	dsb := pcapngBlock(le, 0x0A, make([]byte, 8))
	badTrailer := idb(le, 128)
	badTrailer[len(badTrailer)-1] ^= 1
	badMagic := shb(le)
	badMagic[8] = 0
	huge := make([]byte, 12)
	le.PutUint32(huge, pcapngIDB)
	le.PutUint32(huge[4:], MaxPCAPNGBlock+4)
	for name, b := range map[string][]byte{
		"empty":                    nil,
		"no section header":        idb(le, 128),
		"byte-order magic":         badMagic,
		"trailer length":           append(shb(le), badTrailer...),
		"name resolution block":    append(append(shb(le), idb(le, 128)...), nrb...),
		"decryption secrets block": append(shb(le), dsb...),
		"packet without interface": append(shb(le), epb(le, 0, 10, 10)...),
		"captured beyond snaplen":  bytes.Join([][]byte{shb(le), idb(le, 64), epb(le, 0, 96, 96)}, nil),
		"captured beyond original": bytes.Join([][]byte{shb(le), idb(le, 0), epb(le, 0, 96, 50)}, nil),
		"truncated stream":         append(shb(le), idb(le, 128)[:10]...),
		"oversized block":          append(shb(le), huge...),
	} {
		c, _ := v.NativeCheck(e, ContextManifest{})
		if err := runCheck(t, c, b, 5); err == nil {
			t.Fatal("accepted invalid PCAPNG:", name)
		}
	}
}

func TestSyscallAndHTTPNativeChecks(t *testing.T) {
	v, e, _, _, _ := recorderFixture(t)
	e.NativeType = artifact.SyscallRecordsArtifact
	from := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m := ContextManifest{StartedAt: from, CompletedAt: from.Add(time.Minute)}
	line := func(pod, at, outcome string) string {
		s := `{"identity":{"process_ref":"p1","thread_ref":"t1","pod_uid":"` + pod + `"},"syscall":"openat","abi":"x86_64","timestamp":"` + at + `","outcome":"` + outcome + `"`
		if outcome == "error" {
			s += `,"errno":"ENOENT"`
		}
		return s + "}\n"
	}
	good := line(e.PodUID, "2026-10-09T12:00:01Z", "success") + line(e.PodUID, "2026-10-09T12:00:30.5Z", "error")
	for _, step := range []int{1, 13, len(good)} {
		c, err := v.NativeCheck(e, m)
		if err != nil {
			t.Fatal(err)
		}
		if err = runCheck(t, c, []byte(good), step); err != nil {
			t.Fatal("valid syscall records", err)
		}
	}
	quiet, _ := v.NativeCheck(e, m)
	if err := runCheck(t, quiet, nil, 1); err != nil {
		t.Fatal("a quiet interval has zero records", err)
	}
	for name, b := range map[string]string{
		"foreign pod":          line("other-pod", "2026-10-09T12:00:01Z", "success"),
		"outside the interval": line(e.PodUID, "2026-10-09T12:02:00Z", "success"),
		"error without errno":  strings.Replace(line(e.PodUID, "2026-10-09T12:00:01Z", "success"), "success", "error", 1),
		"argument field":       strings.Replace(line(e.PodUID, "2026-10-09T12:00:01Z", "success"), `"abi"`, `"args":"secret","abi"`, 1),
		"missing newline":      strings.TrimSuffix(line(e.PodUID, "2026-10-09T12:00:01Z", "success"), "\n"),
		"empty line":           "\n",
		"duplicate key":        strings.Replace(line(e.PodUID, "2026-10-09T12:00:01Z", "success"), `"abi":"x86_64"`, `"abi":"x86_64","abi":"arm64"`, 1),
		"oversized event":      `{"syscall":"` + strings.Repeat("a", MaxSyscallEvent) + `"}` + "\n",
	} {
		c, _ := v.NativeCheck(e, m)
		if err := runCheck(t, c, []byte(b), 9); err == nil {
			t.Fatal("accepted invalid syscall records:", name)
		}
	}
	e.NativeType = artifact.HTTPHeadersArtifact
	e.Registration.NativeLimit = artifact.HTTPHeadersNativeLimit
	for name, b := range map[string]struct {
		body string
		ok   bool
	}{
		"object":        {`{"format":"http-response-headers/v1","responses":[]}`, true},
		"array":         {`[]`, false},
		"duplicate key": {`{"a":1,"a":2}`, false},
		"trailing":      {`{"a":1} {}`, false},
		"pcap bytes":    {string(shb(le())), false},
	} {
		c, err := v.NativeCheck(e, m)
		if err != nil {
			t.Fatal(err)
		}
		if err = runCheck(t, c, []byte(b.body), 3); (err == nil) != b.ok {
			t.Fatal("HTTP projection check", name, err)
		}
	}
	c, _ := v.NativeCheck(e, m)
	if err := c.Write(make([]byte, artifact.HTTPHeadersNativeLimit+1)); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("HTTP projection above its bound", err)
	}
	e.NativeType = "core"
	if _, err := v.NativeCheck(e, m); err == nil {
		t.Fatal("unregistered type has a check")
	}
}

func le() binary.ByteOrder { return binary.LittleEndian }
