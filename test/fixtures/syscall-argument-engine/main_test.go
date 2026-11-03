//go:build ignore

package main

import (
	"encoding/binary"
	"testing"
)

func TestNativeRecordAccountingRejectsMalformedAndSeparatesFailedReads(t *testing.T) {
	var c counts
	for _, n := range []int{0, 159, 168} {
		if c.add(make([]byte, n)) == nil {
			t.Fatal("malformed record length accepted", n)
		}
	}
	raw := make([]byte, 160)
	for kind := uint32(0); kind < 3; kind++ {
		binary.LittleEndian.PutUint32(raw, kind)
		if err := c.add(raw); err != nil {
			t.Fatal(err)
		}
	}
	raw[153] = 1
	if err := c.add(raw); err != nil {
		t.Fatal(err)
	}
	if c != (counts{Entries: 1, Exits: 1, Continuations: 2, FailedReads: 1}) {
		t.Fatal(c)
	}
	binary.LittleEndian.PutUint32(raw, 3)
	if c.add(raw) == nil {
		t.Fatal("unknown record type accepted")
	}
}

func TestNativeRecordAccountingIgnoresDocumentedPerfPadding(t *testing.T) {
	for padding := 0; padding <= 7; padding++ {
		raw := make([]byte, 160+padding)
		binary.LittleEndian.PutUint32(raw, 2)
		raw[153] = 1
		for n := 160; n < len(raw); n++ {
			raw[n] = 0xff // padding is not required to be zero
		}
		var c counts
		if err := c.add(raw); err != nil || c != (counts{Continuations: 1, FailedReads: 1}) {
			t.Fatalf("padding=%d: counts=%+v error=%v", padding, c, err)
		}
	}
}

func TestNativeAssertionsRejectUnchargedOutputAndReplenishedBudget(t *testing.T) {
	s := scenario{Name: "entry", Request: workloadRequest{Calls: 1}}
	valid := result{Initial: budget{Events: 4, Bytes: 1024}, Final: budget{Events: 2, Bytes: 256}, Counts: counts{Entries: 1, Exits: 1, Continuations: 1}}
	validate(s, valid)
	for _, changed := range []result{
		{Initial: valid.Initial, Final: budget{Events: 5, Bytes: 256}, Counts: valid.Counts},
		{Initial: valid.Initial, Final: budget{Events: 2, Bytes: 1024}, Counts: valid.Counts},
		{Initial: valid.Initial, Final: valid.Final, Counts: counts{Entries: 2, Exits: 2, Continuations: 2}},
		{Initial: valid.Initial, Final: valid.Final, Counts: counts{Entries: 1, Exits: 1, Continuations: 1, Lost: 1}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid native accounting report accepted", changed)
				}
			}()
			validate(s, changed)
		}()
	}
}

func TestFailedByteReservationMustKeepItsEventDebit(t *testing.T) {
	s := scenario{Name: "insufficient-first-read"}
	valid := result{Initial: budget{Events: 100, Bytes: 511}, Final: budget{Events: 99, Bytes: 511, Stopped: 1}}
	validate(s, valid)
	valid.Final.Events++
	defer func() {
		if recover() == nil {
			t.Fatal("refunded event accepted after insufficient bytes")
		}
	}()
	validate(s, valid)
}
