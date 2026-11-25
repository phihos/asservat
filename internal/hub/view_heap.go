package hub

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// A Java heap dump (HPROF) is summarised by the hub as the heap analysers
// begin: the classes with the number and size of their objects (the
// histogram of VisualVM and Eclipse MAT), the biggest single objects, the
// kinds of GC roots, and the threads' stacks, which the dump holds too. The
// hub reads the dump once, as a stream, and keeps the summary for the view;
// the objects themselves are neither kept nor shown.

// heapSummary is what the viewer shows of a heap dump.
type heapSummary struct {
	Format string `json:"format"`
	// IDSize is the size of an object reference in the dump, in bytes.
	IDSize int `json:"idSize"`
	// Compressed tells that sizes are computed for references of 4 bytes.
	Compressed bool  `json:"compressed"`
	Time       int64 `json:"time"` // when the dump was written, milliseconds since 1970
	Objects    int64 `json:"objects"`
	Bytes      int64 `json:"bytes"`
	// Classes are all classes that have objects, the largest first.
	Classes []heapClass `json:"classes"`
	// Loaded is the number of classes the dump names, with or without objects.
	Loaded  int            `json:"loaded"`
	Biggest []heapObject   `json:"biggest"`
	Roots   map[string]int `json:"roots"`
	// Roots and Threads are those of a Java dump; a .NET dump has neither.
	Threads []heapThread `json:"threads"`
}

type heapClass struct {
	Name      string `json:"name"`
	Instances int64  `json:"instances"`
	Bytes     int64  `json:"bytes"`
}

// heapObject is one object: its class, size and, for an array, its length.
type heapObject struct {
	Class  string `json:"class"`
	Bytes  int64  `json:"bytes"`
	Length int64  `json:"length,omitempty"`
	Array  bool   `json:"array,omitempty"`
}

type heapThread struct {
	Serial uint32   `json:"serial"`
	Frames []string `json:"frames"`
}

// biggestObjects is how many single objects the summary lists: a list for a
// person to read.
const biggestObjects = 100

// The names of the kinds of GC roots, by the tag of their record.
var heapRoots = map[byte]string{
	0xff: "unknown", 0x01: "JNI global", 0x02: "JNI local", 0x03: "Java frame", 0x04: "native stack",
	0x05: "system class", 0x06: "thread block", 0x07: "busy monitor", 0x08: "thread",
}

// The names of the primitive types, by their number in the dump, and the
// sizes of their values.
var heapTypes = map[byte]struct {
	name string
	size int
}{4: {"boolean", 1}, 5: {"char", 2}, 6: {"float", 4}, 7: {"double", 8}, 8: {"byte", 1}, 9: {"short", 2}, 10: {"int", 4}, 11: {"long", 8}}

// heapReader reads a dump's records in the order of the stream.
type heapReader struct {
	r      *bufio.Reader
	idSize int
	buf    [8]byte
}

func (h *heapReader) bytes(n int) ([]byte, error) {
	_, err := io.ReadFull(h.r, h.buf[:n])
	return h.buf[:n], err
}
func (h *heapReader) u1() (byte, error) { return h.r.ReadByte() }
func (h *heapReader) u2() (uint16, error) {
	b, err := h.bytes(2)
	return binary.BigEndian.Uint16(b), err
}
func (h *heapReader) u4() (uint32, error) {
	b, err := h.bytes(4)
	return binary.BigEndian.Uint32(b), err
}
func (h *heapReader) id() (uint64, error) {
	b, err := h.bytes(h.idSize)
	if h.idSize == 4 {
		return uint64(binary.BigEndian.Uint32(b)), err
	}
	return binary.BigEndian.Uint64(b), err
}
func (h *heapReader) skip(n int64) error {
	_, err := io.CopyN(io.Discard, h.r, n)
	return err
}

// valueSize is the size of a field or element of a type in the dump.
func (h *heapReader) valueSize(kind byte) (int, error) {
	if kind == 2 {
		return h.idSize, nil
	}
	t, ok := heapTypes[kind]
	if !ok {
		return 0, fmt.Errorf("unknown value type %d", kind)
	}
	return t.size, nil
}

// heapTally counts the objects of a class, or one object, with their size
// in the two ways a JVM lays objects out: with references of four bytes
// ("compressed", its default below 32 GiB of heap) and with plain ones. A
// dump always holds references in full and does not tell which it was.
type heapTally struct {
	class             uint64
	instances         int64
	compressed, plain int64
	length            int64
	array             bool
}

// heapLayout is what a class adds to its objects: references and bytes of
// primitive values, on top of its superclass's.
type heapLayout struct {
	super       uint64
	refs, bytes int64
}

// heapName is how much the hub keeps of a string of a heap dump: 64 KiB,
// the longest name a class file can give a class, a method or a field.
const heapName = 64 << 10

// summarizeHeap reads a heap dump and returns its summary.
//
// The size of an object is computed as heap analysers do: the header (12
// bytes with compressed references, 16 without, and 4 more for an array's
// length) plus its fields or elements, rounded up to 8 bytes. References
// are taken as compressed when the dump's objects lie within 32 GiB, as
// the JVM does by default; then the sizes are those of the JVM's own class
// histogram.
func summarizeHeap(dump io.Reader) (*heapSummary, error) {
	h := &heapReader{r: bufio.NewReaderSize(dump, 1<<20)}
	format, err := h.r.ReadString(0)
	if err != nil || !strings.HasPrefix(format, "JAVA PROFILE 1.0") {
		return nil, errors.New("the file does not begin as a heap dump in HPROF format")
	}
	size, err := h.u4()
	if err != nil || (size != 4 && size != 8) {
		return nil, errors.New("the dump's reference size is neither 4 nor 8 bytes")
	}
	h.idSize = int(size)
	stamp, err := h.bytes(8)
	if err != nil {
		return nil, err
	}
	sum := &heapSummary{Format: strings.TrimSuffix(format, "\x00"), IDSize: h.idSize, Time: int64(binary.BigEndian.Uint64(stamp)), Roots: map[string]int{}, Threads: []heapThread{}}

	strs := map[uint64]string{}       // the names of classes, methods and files
	classNames := map[uint64]uint64{} // class object -> name
	classSerials := map[uint32]uint64{}
	classes := map[uint64]*heapTally{} // by class object; primitive arrays by their type's number
	layouts := map[uint64]heapLayout{}
	var biggest []heapTally
	lowest, highest := ^uint64(0), uint64(0) // the addresses of the objects
	type frame struct {
		method, file uint64
		class        uint32
		line         int32
	}
	frames := map[uint64]frame{}
	traces := map[uint32][]uint64{} // stack trace -> frames
	threads := map[uint32]uint32{}  // thread -> stack trace
	wanted := map[uint64]bool{}     // strings that name a class, a method or a file
	pending := map[uint64][]byte{}  // strings read before it was known whether they are wanted
	align := func(n int64) int64 { return (n + 7) &^ 7 }
	// count adds an object: an array by its size both ways, an object of a
	// class by its size in the dump until the classes' layouts are known.
	count := func(id uint64, object heapTally) {
		lowest, highest = min(lowest, id), max(highest, id)
		c := classes[object.class]
		if c == nil {
			c = &heapTally{class: object.class, array: object.array}
			classes[object.class] = c
		}
		c.instances++
		c.compressed += object.compressed
		c.plain += object.plain
		sum.Objects++
		biggest = keepBiggest(biggest, object, func(t heapTally) int64 { return t.plain })
	}
	ref := int64(h.idSize)

	for {
		tag, err := h.u1()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if _, err := h.u4(); err != nil { // time since the dump began
			return nil, truncated(err)
		}
		length, err := h.u4()
		if err != nil {
			return nil, truncated(err)
		}
		switch tag {
		case 0x01: // a string
			id, err := h.id()
			if err != nil {
				return nil, truncated(err)
			}
			// The record says how long it is; the memory for it is taken
			// as the bytes arrive, not on the record's word.
			if int64(length) < int64(h.idSize) {
				return nil, errors.New("a string record is shorter than its ID")
			}
			// Kept is what names a class, a method or a file, which is
			// short: of a longer string its beginning, so that a dump of
			// strings is not held in memory whole.
			size := int64(length) - int64(h.idSize)
			text, err := io.ReadAll(io.LimitReader(h.r, min(size, heapName)))
			if err == nil && int64(len(text)) != min(size, heapName) {
				err = io.ErrUnexpectedEOF
			}
			if err == nil && size > heapName {
				if n, e := io.CopyN(io.Discard, h.r, size-heapName); e != nil || n != size-heapName {
					err = io.ErrUnexpectedEOF
				}
			}
			if err != nil {
				return nil, truncated(err)
			}
			// Most strings name fields. Kept are those that a class, a
			// method or a file is named by, which is known later.
			if wanted[id] {
				strs[id] = string(text)
			} else {
				pending[id] = text
			}
		case 0x02: // a loaded class
			serial, _ := h.u4()
			class, _ := h.id()
			h.u4()
			name, err := h.id()
			if err != nil {
				return nil, truncated(err)
			}
			classNames[class], classSerials[serial] = name, class
			sum.Loaded++
			want(name, wanted, pending, strs)
		case 0x04: // a stack frame
			id, _ := h.id()
			method, _ := h.id()
			h.id()
			file, _ := h.id()
			class, _ := h.u4()
			line, err := h.u4()
			if err != nil {
				return nil, truncated(err)
			}
			frames[id] = frame{method: method, file: file, class: class, line: int32(line)}
			want(method, wanted, pending, strs)
			want(file, wanted, pending, strs)
		case 0x05: // a stack trace
			serial, _ := h.u4()
			h.u4()
			n, err := h.u4()
			if err != nil {
				return nil, truncated(err)
			}
			// As many frames as the file holds, whatever number it names.
			var ids []uint64
			for range n {
				id, err := h.id()
				if err != nil {
					return nil, truncated(err)
				}
				ids = append(ids, id)
			}
			traces[serial] = ids
		case 0x0c, 0x1c: // a part of the heap
			left := int64(length)
			for left > 0 {
				sub, err := h.u1()
				if err != nil {
					return nil, truncated(err)
				}
				left--
				switch sub {
				case 0xff, 0x05, 0x07:
					err = h.skip(int64(h.idSize))
					left -= int64(h.idSize)
				case 0x01:
					err = h.skip(int64(2 * h.idSize))
					left -= int64(2 * h.idSize)
				case 0x02, 0x03:
					err = h.skip(int64(h.idSize + 8))
					left -= int64(h.idSize + 8)
				case 0x04, 0x06:
					err = h.skip(int64(h.idSize + 4))
					left -= int64(h.idSize + 4)
				case 0x08: // a thread and its stack trace
					h.id()
					var thread, trace uint32
					thread, _ = h.u4()
					trace, err = h.u4()
					threads[thread] = trace
					left -= int64(h.idSize + 8)
				case 0x20: // a class: its constants, static fields and the types of its fields
					var class uint64
					var layout heapLayout
					class, _ = h.id()
					h.u4()
					layout.super, _ = h.id()
					if err = h.skip(int64(5*h.idSize + 4)); err != nil {
						break
					}
					left -= int64(7*h.idSize + 8)
					for _, named := range []bool{false, true} { // constants by index, static fields by name
						var n uint16
						if n, err = h.u2(); err != nil {
							break
						}
						left -= 2
						for range n {
							lead := int64(2)
							if named {
								lead = int64(h.idSize)
							}
							h.skip(lead)
							var kind byte
							var size int
							if kind, err = h.u1(); err != nil {
								break
							}
							if size, err = h.valueSize(kind); err != nil {
								break
							}
							err = h.skip(int64(size))
							left -= lead + 1 + int64(size)
						}
						if err != nil {
							break
						}
					}
					if err != nil {
						break
					}
					var n uint16
					if n, err = h.u2(); err != nil {
						break
					}
					left -= 2 + int64(n)*int64(h.idSize+1)
					for range n {
						h.id()
						var kind byte
						var size int
						if kind, err = h.u1(); err != nil {
							break
						}
						if size, err = h.valueSize(kind); err != nil {
							break
						}
						if kind == 2 {
							layout.refs++
						} else {
							layout.bytes += int64(size)
						}
					}
					layouts[class] = layout
				case 0x21: // an object
					var id, class uint64
					var n uint32
					id, _ = h.id()
					h.u4()
					class, _ = h.id()
					if n, err = h.u4(); err != nil {
						break
					}
					err = h.skip(int64(n))
					left -= int64(2*h.idSize+8) + int64(n)
					count(id, heapTally{class: class, compressed: int64(n), plain: int64(n)})
				case 0x22: // an array of objects
					var id, class uint64
					var n uint32
					id, _ = h.id()
					h.u4()
					n, _ = h.u4()
					if class, err = h.id(); err != nil {
						break
					}
					err = h.skip(int64(n) * ref)
					left -= int64(2*h.idSize+8) + int64(n)*ref
					count(id, heapTally{class: class, compressed: align(16 + int64(n)*4), plain: align(20 + int64(n)*ref), length: int64(n), array: true})
				case 0x23: // an array of primitive values
					var id uint64
					var n uint32
					var kind byte
					var size int
					id, _ = h.id()
					h.u4()
					n, _ = h.u4()
					if kind, err = h.u1(); err != nil {
						break
					}
					if size, err = h.valueSize(kind); err != nil {
						break
					}
					err = h.skip(int64(n) * int64(size))
					left -= int64(h.idSize+9) + int64(n)*int64(size)
					count(id, heapTally{class: uint64(kind), compressed: align(16 + int64(n)*int64(size)), plain: align(20 + int64(n)*int64(size)), length: int64(n), array: true})
				default:
					err = fmt.Errorf("unknown record %#x in the heap", sub)
				}
				if err != nil {
					return nil, truncated(err)
				}
				if name, ok := heapRoots[sub]; ok {
					sum.Roots[name]++
				}
			}
		default:
			if err := h.skip(int64(length)); err != nil {
				return nil, truncated(err)
			}
		}
	}

	// The classes by their names, as Java writes them.
	named := func(key uint64) string {
		if t, ok := heapTypes[byte(key)]; ok && key < 16 {
			return t.name + "[]"
		}
		if name, ok := strs[classNames[key]]; ok {
			return javaName(name)
		}
		return fmt.Sprintf("class at 0x%x", key)
	}
	// References are compressed where the JVM can address all objects with
	// 32 bits: within 32 GiB.
	compressed := h.idSize == 8 && highest >= lowest && highest-lowest < 32<<30
	sum.Compressed = compressed
	// sizeOf is the size of an object or of all objects of a class.
	sizeOf := func(t heapTally) int64 {
		if t.array {
			if compressed {
				return t.compressed
			}
			return t.plain
		}
		// An object of a class: its header and the fields of the class and its superclasses.
		refs, bytes, known := int64(0), int64(0), true
		for class, depth := t.class, 0; class != 0; depth++ {
			layout, ok := layouts[class]
			if !ok || depth > len(layouts) {
				known = false
				break
			}
			refs, bytes, class = refs+layout.refs, bytes+layout.bytes, layout.super
		}
		instances := max(t.instances, 1)
		switch {
		case !known: // a class the dump does not describe: its objects as the dump holds them
			return t.plain + instances*align(16)
		case compressed:
			return instances * align(12+refs*4+bytes)
		default:
			return instances * align(16+refs*ref+bytes)
		}
	}
	for key, c := range classes {
		class := heapClass{Name: named(key), Instances: c.instances, Bytes: sizeOf(*c)}
		sum.Bytes += class.Bytes
		sum.Classes = append(sum.Classes, class)
	}
	sort.Slice(sum.Classes, func(i, j int) bool {
		a, b := sum.Classes[i], sum.Classes[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.Name < b.Name
	})
	for _, o := range biggest {
		sum.Biggest = append(sum.Biggest, heapObject{Class: named(o.class), Bytes: sizeOf(o), Length: o.length, Array: o.array})
	}
	sort.SliceStable(sum.Biggest, func(i, j int) bool { return sum.Biggest[i].Bytes > sum.Biggest[j].Bytes })
	// The threads' stacks, as a thread dump writes them.
	for thread, trace := range threads {
		t := heapThread{Serial: thread, Frames: []string{}}
		for _, id := range traces[trace] {
			f := frames[id]
			where := strs[f.file]
			switch {
			case f.line > 0:
				where += fmt.Sprintf(":%d", f.line)
			case f.line == -3:
				where = "Native Method"
			case where == "":
				where = "Unknown Source"
			}
			t.Frames = append(t.Frames, fmt.Sprintf("%s.%s(%s)", javaName(strs[classNames[classSerials[f.class]]]), strs[f.method], where))
		}
		sum.Threads = append(sum.Threads, t)
	}
	sort.Slice(sum.Threads, func(i, j int) bool { return sum.Threads[i].Serial < sum.Threads[j].Serial })
	return sum, nil
}

// want keeps the string with an ID, now or when it is read.
func want(id uint64, wanted map[uint64]bool, pending map[uint64][]byte, strs map[uint64]string) {
	wanted[id] = true
	if text, ok := pending[id]; ok {
		strs[id] = string(text)
		delete(pending, id)
	}
}

// truncated names the end of a dump in the middle of a record.
func truncated(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return errors.New("the dump ends in the middle of a record")
	}
	return err
}

// javaName turns a class name of the JVM into the one Java source uses:
// "java/lang/String" is java.lang.String, "[[I" is int[][].
func javaName(name string) string {
	depth := 0
	for strings.HasPrefix(name, "[") {
		name = name[1:]
		depth++
	}
	if depth > 0 {
		primitive := map[string]string{"Z": "boolean", "C": "char", "F": "float", "D": "double", "B": "byte", "S": "short", "I": "int", "J": "long"}
		if p, ok := primitive[name]; ok {
			name = p
		} else {
			name = strings.TrimSuffix(strings.TrimPrefix(name, "L"), ";")
		}
	}
	return strings.ReplaceAll(name, "/", ".") + strings.Repeat("[]", depth)
}

// heapSummaryOf reads a heap dump, of Java or of .NET by the file's name.
func (h *Hub) heapSummaryOf(ctx context.Context, a storedArtifact) (*heapSummary, error) {
	dump, write := io.Pipe()
	go func() { write.CloseWithError(h.plain(ctx, a, write)) }()
	defer dump.Close() // also when reading the dump panics: the decryption does not wait for a reader that is gone
	summarize := summarizeHeap
	if strings.HasSuffix(a.Name, ".gcdump") {
		summarize = summarizeDotnetHeap
	}
	sum, err := summarize(dump)
	dump.CloseWithError(err) // ends the decryption if the dump was not read to its end
	if err != nil {
		return nil, errStatus{http.StatusUnprocessableEntity, "this heap dump cannot be read: " + err.Error()}
	}
	return sum, nil
}

// heapText returns a heap dump's summary as text, for readers that cannot
// open the viewer: the totals and the largest classes, as a class
// histogram prints them.
func (h *Hub) heapText(ctx context.Context, a storedArtifact) (string, error) {
	sum, err := h.heapSummaryOf(ctx, a)
	if err != nil {
		return "", err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%s: %d objects, %d bytes, %d classes with objects. Sizes are the objects' own (shallow).\n", sum.Format, sum.Objects, sum.Bytes, len(sum.Classes))
	// As many classes as the profile report lists functions.
	fmt.Fprintf(&text, "\nThe largest classes:\n%12s %14s  %s\n", "objects", "bytes", "class")
	for _, c := range sum.Classes[:min(len(sum.Classes), 60)] {
		fmt.Fprintf(&text, "%12d %14d  %s\n", c.Instances, c.Bytes, c.Name)
	}
	text.WriteString("\nThe biggest single objects:\n")
	for _, o := range sum.Biggest[:min(len(sum.Biggest), 20)] {
		fmt.Fprintf(&text, "%14d  %s\n", o.Bytes, o.Class)
	}
	for _, t := range sum.Threads {
		if len(t.Frames) > 0 {
			fmt.Fprintf(&text, "\nThread %d:\n\tat %s\n", t.Serial, strings.Join(t.Frames, "\n\tat "))
		}
	}
	return text.String(), nil
}

// heapPages reads a heap dump and returns the page that holds its summary.
func (h *Hub) heapPages(ctx context.Context, a storedArtifact) (map[string]http.Handler, error) {
	sum, err := h.heapSummaryOf(ctx, a)
	if err != nil {
		return nil, err
	}
	page, err := json.Marshal(sum)
	if err != nil {
		return nil, err
	}
	return map[string]http.Handler{"/summary": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(page)
	})}, nil
}

// keepBiggest adds an object to the list of the biggest, in place of the
// smallest once the list is full.
func keepBiggest[T any](biggest []T, object T, size func(T) int64) []T {
	if len(biggest) < biggestObjects {
		return append(biggest, object)
	}
	least := 0
	for i := range biggest {
		if size(biggest[i]) < size(biggest[least]) {
			least = i
		}
	}
	if size(object) > size(biggest[least]) {
		biggest[least] = object
	}
	return biggest
}

// A .NET heap dump of the kind dotnet-gcdump and dotnet-monitor write
// (*.gcdump) holds the heap's objects as a graph, without their contents:
// for every object its type and size and what it refers to. The file is
// PerfView's serialization of that graph: the types, then for every object
// the place of its record, then the records. The summary counts the
// objects of each type, as "dotnet-gcdump report" does.
func summarizeDotnetHeap(dump io.Reader) (*heapSummary, error) {
	r := bufio.NewReaderSize(dump, 1<<20)
	short := errors.New("the file ends before the heap's objects")
	var buf [8]byte
	i32 := func() (int32, error) {
		_, err := io.ReadFull(r, buf[:4])
		return int32(binary.LittleEndian.Uint32(buf[:4])), err
	}
	// A string is a number of UTF-16 units and then UTF-8, so its length in
	// bytes is only known by reading it; -1 units mean no string.
	str := func() (string, error) {
		units, err := i32()
		if err != nil || units < 0 {
			return "", err
		}
		var text strings.Builder
		for range units {
			lead, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			text.WriteByte(lead)
			more := 0
			switch {
			case lead >= 0xe0:
				more = 2
			case lead >= 0xc0:
				more = 1
			}
			for range more {
				b, err := r.ReadByte()
				if err != nil {
					return "", err
				}
				text.WriteByte(b)
			}
		}
		return strings.ToValidUTF8(text.String(), "?"), nil
	}
	// An object begins with a tag and its type: a tag, an empty reference,
	// two versions, the type's name and a closing tag.
	object := func(named string) error {
		var head [3]byte
		if _, err := io.ReadFull(r, head[:]); err != nil || (head[0] != 4 && head[0] != 5) || (head[1] != 4 && head[1] != 5) || head[2] != 1 {
			return fmt.Errorf("no %s where one is expected", named)
		}
		i32()
		i32()
		name, err := str()
		if end, _ := r.ReadByte(); err != nil || name != named || end != 6 {
			return fmt.Errorf("no %s where one is expected", named)
		}
		return nil
	}
	if magic, err := str(); err != nil || magic != "!FastSerialization.1" {
		return nil, errors.New("the file does not begin as a .NET heap dump (gcdump)")
	}
	if err := object("GCHeapDump"); err != nil {
		return nil, err
	}
	if err := object("Graphs.MemoryGraph"); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, buf[:8]); err != nil { // the size of all objects, counted again below
		return nil, short
	}
	i32() // the graph's root
	count, err := i32()
	if err != nil || count < 0 {
		return nil, short
	}
	type kind struct {
		name string
		size int32
	}
	// The lists grow as they are read: a count in the file allocates nothing.
	var kinds []kind
	for range count {
		name, err := str()
		if err != nil {
			return nil, short
		}
		size, _ := i32()
		if _, err := str(); err != nil { // the module that defines the type
			return nil, short
		}
		kinds = append(kinds, kind{name, size})
	}
	if count, err = i32(); err != nil || count < 0 {
		return nil, short
	}
	var places []uint32
	for range count {
		place, err := i32()
		if err != nil {
			return nil, short
		}
		places = append(places, uint32(place))
	}
	sort.Slice(places, func(i, j int) bool { return places[i] < places[j] })
	length, err := i32()
	if err != nil || length < 0 {
		return nil, short
	}
	// A record begins with two numbers of 7 bits per byte: the type, with a
	// bit that tells whether the size follows or is the type's.
	at := uint32(0)
	number := func() (int32, error) {
		var n int32
		for i := 0; i < 5; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return 0, err
			}
			at++
			if i == 0 {
				n = int32(int8(b<<1)) >> 1 // the first byte holds the sign
			} else {
				n = n<<7 + int32(b&0x7f)
			}
			if b&0x80 == 0 {
				break
			}
		}
		return n, nil
	}
	sum := &heapSummary{Format: ".NET gcdump"}
	types := map[int32]*heapClass{}
	type single struct {
		kind int32
		size int64
	}
	var biggest []single
	for _, place := range places {
		if place < at || place >= uint32(length) {
			continue // the same record again, or none
		}
		if _, err := r.Discard(int(place - at)); err != nil {
			return nil, short
		}
		at = place
		typeAndSize, err := number()
		if err != nil {
			return nil, short
		}
		index := typeAndSize >> 1
		if index < 0 || int(index) >= len(kinds) {
			return nil, errors.New("an object whose type the dump does not define")
		}
		size := kinds[index].size
		if typeAndSize&1 != 0 {
			if size, err = number(); err != nil {
				return nil, short
			}
		}
		// Records without a size are the graph's own nodes: its roots and their groups.
		if size <= 0 {
			continue
		}
		c := types[index]
		if c == nil {
			c = &heapClass{Name: kinds[index].name}
			types[index] = c
		}
		c.Instances++
		c.Bytes += int64(size)
		sum.Objects++
		sum.Bytes += int64(size)
		biggest = keepBiggest(biggest, single{index, int64(size)}, func(s single) int64 { return s.size })
	}
	sum.Loaded = len(kinds)
	for _, c := range types {
		sum.Classes = append(sum.Classes, *c)
	}
	sort.Slice(sum.Classes, func(i, j int) bool {
		a, b := sum.Classes[i], sum.Classes[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.Name < b.Name
	})
	sort.SliceStable(biggest, func(i, j int) bool { return biggest[i].size > biggest[j].size })
	for _, o := range biggest {
		sum.Biggest = append(sum.Biggest, heapObject{Class: kinds[o.kind].name, Bytes: o.size})
	}
	return sum, nil
}
