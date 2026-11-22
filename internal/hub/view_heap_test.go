package hub_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// syntheticHeap writes a heap dump in HPROF format with references of 8
// bytes: three shop.Order objects (a long and a reference each), an array of
// them, an array of 100 bytes, and one thread with one frame.
func syntheticHeap() []byte {
	var dump bytes.Buffer
	u := func(values ...any) []byte {
		var b bytes.Buffer
		for _, v := range values {
			binary.Write(&b, binary.BigEndian, v)
		}
		return b.Bytes()
	}
	record := func(tag byte, body []byte) {
		dump.Write(u(tag, uint32(0), uint32(len(body))))
		dump.Write(body)
	}
	dump.WriteString("JAVA PROFILE 1.0.2\x00")
	dump.Write(u(uint32(8), uint64(1700000000000)))
	for id, text := range []string{"", "java/lang/Object", "shop/Order", "[Lshop/Order;", "run", "Order.java", "()V", "id", "next"} {
		if id > 0 {
			record(0x01, append(u(uint64(id)), text...))
		}
	}
	for serial, class := range map[uint32]uint64{1: 0x100, 2: 0x200, 3: 0x300} {
		record(0x02, u(serial, class, uint32(0), uint64(serial))) // the class's name is the string of its serial
	}
	record(0x04, u(uint64(0x900), uint64(4), uint64(6), uint64(5), uint32(2), int32(12)))
	record(0x05, u(uint32(7), uint32(1), uint32(1), uint64(0x900)))
	var heap bytes.Buffer
	heap.Write(u(byte(0x08), uint64(0x500), uint32(1), uint32(7))) // the thread, with its stack trace
	class := func(id, super uint64, fields ...any) {
		heap.Write(u(byte(0x20), id, uint32(0), super, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint32(16)))
		heap.Write(u(uint16(1), uint16(1), byte(10), int32(5))) // one constant, an int
		heap.Write(u(uint16(1), uint64(7), byte(2), uint64(0))) // one static field, a reference
		heap.Write(u(uint16(len(fields) / 2)))
		heap.Write(u(fields...))
	}
	class(0x100, 0)
	class(0x200, 0x100, uint64(7), byte(11), uint64(8), byte(2)) // a long and a reference
	for i := range 3 {
		heap.Write(u(byte(0x21), uint64(0x1000+i*32), uint32(0), uint64(0x200), uint32(16), uint64(i), uint64(0)))
	}
	heap.Write(u(byte(0x22), uint64(0x2000), uint32(0), uint32(3), uint64(0x300), uint64(0x1000), uint64(0x1020), uint64(0x1040)))
	heap.Write(u(byte(0x23), uint64(0x3000), uint32(0), uint32(100), byte(8)))
	heap.Write(make([]byte, 100))
	record(0x1c, heap.Bytes())
	record(0x2c, nil)
	return dump.Bytes()
}

// A Java heap dump opens as its summary: the classes with the number and
// size of their objects as the JVM's class histogram gives them, the biggest
// objects, the GC roots and the threads' stacks.
func TestHeapDumpView(t *testing.T) {
	dump := syntheticHeap()
	f, capture, _ := viewed(t, map[string][]byte{"api-1/heapdump.hprof": dump, "api-1/cut.hprof": dump[:len(dump)-60], "api-1/other.hprof": []byte("no heap dump")})
	view := openedView(t, f, capture, "api-1/heapdump.hprof")
	code, b := f.call("alice-token", "GET", "/api/views/"+view+"/pages/summary", nil)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var heap struct {
		Objects, Bytes int64
		Compressed     bool
		Loaded         int
		Classes        []struct {
			Name             string
			Instances, Bytes int64
		}
		Biggest []struct {
			Class         string
			Bytes, Length int64
		}
		Roots   map[string]int
		Threads []struct{ Frames []string }
	}
	if err := json.Unmarshal(b, &heap); err != nil {
		t.Fatal(err, string(b))
	}
	// With compressed references: an Order is 12 + 8 + 4 bytes, the array of
	// three 16 + 3*4 rounded up, the bytes 16 + 100 rounded up.
	if heap.Objects != 5 || heap.Bytes != 3*24+32+120 || !heap.Compressed || heap.Loaded != 3 || len(heap.Classes) != 3 {
		t.Fatal(string(b))
	}
	if c := heap.Classes[0]; c.Name != "byte[]" || c.Instances != 1 || c.Bytes != 120 {
		t.Fatal("the largest class", c)
	}
	if c := heap.Classes[1]; c.Name != "shop.Order" || c.Instances != 3 || c.Bytes != 72 {
		t.Fatal("the objects of a class", c)
	}
	if c := heap.Classes[2]; c.Name != "shop.Order[]" || c.Bytes != 32 {
		t.Fatal("an array of objects", c)
	}
	if o := heap.Biggest[0]; o.Class != "byte[]" || o.Bytes != 120 || o.Length != 100 || len(heap.Biggest) != 5 {
		t.Fatal("the biggest object", heap.Biggest)
	}
	if heap.Roots["thread"] != 1 || len(heap.Threads) != 1 || strings.Join(heap.Threads[0].Frames, "|") != "shop.Order.run(Order.java:12)" {
		t.Fatal("roots and threads", heap.Roots, heap.Threads)
	}
	if code, _ := f.call("root-token", "GET", "/api/views/"+view+"/pages/summary", nil); code != 404 {
		t.Fatal("another user's view", code)
	}
	for _, name := range []string{"cut.hprof", "other.hprof"} {
		if code, b := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/"+name, nil); code != 422 || !strings.Contains(string(b), "heap dump") {
			t.Fatal(name, code, string(b))
		}
	}
}

// syntheticDotnetHeap writes a .NET heap dump (gcdump): two shop.Order
// objects of the type's size, two strings with sizes of their own, and the
// graph's root, which has no size.
func syntheticDotnetHeap() []byte {
	var dump bytes.Buffer
	i32 := func(n int32) { binary.Write(&dump, binary.LittleEndian, n) }
	str := func(s string) { i32(int32(len(s))); dump.WriteString(s) }
	object := func(name string) {
		dump.Write([]byte{4, 4, 1})
		i32(1)
		i32(0)
		str(name)
		dump.WriteByte(6)
	}
	str("!FastSerialization.1")
	object("GCHeapDump")
	object("Graphs.MemoryGraph")
	binary.Write(&dump, binary.LittleEndian, int64(414)) // the size of all objects
	i32(0)                                               // the root
	i32(3)
	for _, kind := range []struct {
		name string
		size int32
	}{{"[.NET Roots]", 0}, {"shop.Order", 32}, {"System.String", 0}} {
		str(kind.name)
		i32(kind.size)
		i32(-1) // no module
	}
	records := [][]byte{
		{0 << 1, 2, 1, 2},           // the root, with two references
		{1 << 1, 0},                 // an Order of the type's size
		{1 << 1, 0},                 // another
		{2<<1 | 1, 50, 0},           // a string of 50 bytes
		{2<<1 | 1, 0x80 | 2, 44, 0}, // a string of 300 bytes, in two bytes
	}
	i32(int32(len(records)))
	place := int32(0)
	for _, record := range records {
		i32(place)
		place += int32(len(record))
	}
	i32(place)
	for _, record := range records {
		dump.Write(record)
	}
	return dump.Bytes()
}

// A .NET heap dump opens in the same viewer: its types with the number and
// size of their objects, as "dotnet-gcdump report" counts them.
func TestDotnetHeapDumpView(t *testing.T) {
	dump := syntheticDotnetHeap()
	f, capture, _ := viewed(t, map[string][]byte{"api-1/heap.gcdump": dump, "api-1/cut.gcdump": dump[:len(dump)-6], "api-1/other.gcdump": []byte("no heap dump")})
	view := openedView(t, f, capture, "api-1/heap.gcdump")
	code, b := f.call("alice-token", "GET", "/api/views/"+view+"/pages/summary", nil)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var heap struct {
		Format         string
		Objects, Bytes int64
		Classes        []struct {
			Name             string
			Instances, Bytes int64
		}
		Biggest []struct {
			Class string
			Bytes int64
		}
	}
	if err := json.Unmarshal(b, &heap); err != nil {
		t.Fatal(err, string(b))
	}
	if heap.Format != ".NET gcdump" || heap.Objects != 4 || heap.Bytes != 414 || len(heap.Classes) != 2 {
		t.Fatal(string(b))
	}
	if c := heap.Classes[0]; c.Name != "System.String" || c.Instances != 2 || c.Bytes != 350 {
		t.Fatal("objects with sizes of their own", c)
	}
	if c := heap.Classes[1]; c.Name != "shop.Order" || c.Instances != 2 || c.Bytes != 64 {
		t.Fatal("objects of the type's size", c)
	}
	if o := heap.Biggest[0]; o.Class != "System.String" || o.Bytes != 300 {
		t.Fatal("the biggest object", heap.Biggest)
	}
	for _, name := range []string{"cut.gcdump", "other.gcdump"} {
		if code, b := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/"+name, nil); code != 422 || !strings.Contains(string(b), "heap dump") {
			t.Fatal(name, code, string(b))
		}
	}
}
