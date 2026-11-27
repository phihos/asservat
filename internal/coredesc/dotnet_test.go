package coredesc

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// What dotnet-dump says of the threads, stacks and an exception of a
// synthetic program is read into threads with their frames.
func TestDotnetDumpIsRead(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		content, err := os.ReadFile(filepath.Join("testdata", "dotnet", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	threads := dotnetThreads(read("clrthreads.txt"))
	type thread struct {
		id, system         int
		name, status, held string
	}
	var got []thread
	for _, th := range threads {
		got = append(got, thread{th.ID, th.ThreadSystemID, th.Name, th.Status, th.held})
	}
	// The thread that has ended is not among them.
	want := []thread{
		{1, 0x1, "", "", ""},
		{2, 0x16, "Finalizer", "", ""},
		{4, 0x18, "", "", ""},
		{5, 0x19, "", "holds System.InvalidOperationException", "00007e1cf1800040"},
		{10, 0x1f, "Threadpool Worker", "holds System.TimeoutException", "00007e1cf1800ac8"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("threads: %+v", got)
	}

	frames, cut := dotnetStacks(read("clrstack.txt"))
	if len(frames) != 4 || len(cut) != 0 {
		t.Fatalf("stacks of %d threads, %d cut", len(frames), len(cut))
	}
	// The runtime's marks are left out; the method that one names stays.
	functions := func(system int) string {
		var names []string
		for i, f := range frames[system] {
			if f.Level != i || f.Arguments == nil || f.Locals == nil {
				t.Errorf("frame %d of thread %#x: %+v", i, system, f)
			}
			names = append(names, f.Function)
		}
		return strings.Join(names, " < ")
	}
	for system, want := range map[int]string{
		0x1:  "System.Threading.Monitor.ObjWait(Int32, System.Object) < System.Threading.Monitor.Wait(System.Object, Int32) < Microsoft.Extensions.Hosting.HostingAbstractionsHostExtensions.Run(Microsoft.Extensions.Hosting.IHost) < Shop.Program.Main(System.String[])",
		0x16: "",
		0x19: "System.Threading.Thread.SleepInternal(Int32) < System.Threading.Thread.Sleep(Int32) < Shop.Billing.HoldFailure(System.Exception) < Shop.Billing.Charge(System.Decimal) < Shop.Billing.Fail(System.Decimal) < Shop.Billing.Charge(System.Decimal) < Shop.Program+<>c.<Main>b__0_2()",
		0x1f: "System.Threading.LowLevelLifoSemaphore.WaitNative(Microsoft.Win32.SafeHandles.SafeWaitHandle, Int32) < System.Threading.PortableThreadPool+WorkerThread.WorkerThreadStart()",
	} {
		if got := functions(system); got != want {
			t.Errorf("thread %#x: %s", system, got)
		}
	}
	if f := frames[0x18][2]; f.Function != "Shop.OrderQueue.WaitForOrder(Int32, System.String)" || f.File != "/src/Program.cs" || f.Line != 12 || f.PC != "0x7e5cdf0c1e70" {
		t.Errorf("the frame with a source line: %+v", f)
	}
	if f := frames[0x1][3]; f.Function != "Shop.Program.Main(System.String[])" || f.Line != 43 {
		t.Errorf("the frame of a method that takes an array: %+v", f)
	}
	if f := frames[0x18][0]; f.File != "" || f.Line != 0 {
		t.Errorf("the frame without a source line: %+v", f)
	}

	// A stack is cut after the innermost frames.
	deep := "OS Thread Id: 0x2a\n" + strings.Repeat("00007E5D567BFB30 00007E5CDF0C1E70 Shop.Orders.Next(Int32)\n", maxFrames+1)
	if frames, cut := dotnetStacks(deep); len(frames[0x2a]) != maxFrames || !cut[0x2a] {
		t.Errorf("%d frames of a deep stack, cut: %v", len(frames[0x2a]), cut[0x2a])
	}

	if message := dotnetMessage(read("pe.txt")); message != "card declined for 12.5" {
		t.Errorf("the exception's message: %q", message)
	}
	if message := dotnetMessage("Exception type:   System.Exception\nMessage:          <none>\n"); message != "" {
		t.Errorf("an exception without a message: %q", message)
	}
	if message := dotnetMessage("Message:          " + strings.Repeat("ä", maxValue+10)); message != strings.Repeat("ä", maxValue)+"…" {
		t.Errorf("a long message: %q", message)
	}
}

// syntheticLibrary is a library of the machine with nothing but a build ID.
func syntheticLibrary(machine elf.Machine, id []byte) []byte {
	names := "\x00.note.gnu.build-id\x00.shstrtab\x00"
	note := binary.LittleEndian.AppendUint32(nil, 4)
	note = binary.LittleEndian.AppendUint32(note, uint32(len(id)))
	note = binary.LittleEndian.AppendUint32(note, 3) // NT_GNU_BUILD_ID
	note = append(append(note, "GNU\x00"...), id...)
	var file bytes.Buffer
	header := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(machine), Version: 1, Ehsize: 64, Shentsize: 64, Shnum: 3, Shstrndx: 2}
	copy(header.Ident[:], "\x7fELF\x02\x01\x01")
	header.Shoff = uint64(64 + len(note) + len(names))
	binary.Write(&file, binary.LittleEndian, header)
	file.Write(note)
	file.WriteString(names)
	binary.Write(&file, binary.LittleEndian, []elf.Section64{{},
		{Name: 1, Type: uint32(elf.SHT_NOTE), Off: 64, Size: uint64(len(note)), Addralign: 4},
		{Name: 20, Type: uint32(elf.SHT_STRTAB), Off: uint64(64 + len(note)), Size: uint64(len(names)), Addralign: 1}})
	return file.Bytes()
}

// The helper library of a runtime is fetched from the symbol server by the
// build ID of the runtime's libcoreclr.so, once, and never taken from
// beside it.
func TestDotnetHelperIsFetchedByBuildID(t *testing.T) {
	here, known := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if !known {
		t.Skip("no helper libraries for this processor")
	}
	other := elf.EM_AARCH64
	if here == other {
		other = elf.EM_X86_64
	}
	published := syntheticLibrary(here, []byte("the helper as Microsoft built it"))
	var mu sync.Mutex
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/libmscordaccore.so/elf-buildid-coreclr-00112233445566778899aabbccddeeff00112233/libmscordaccore.so":
			w.Write(published)
		case "/libmscordaccore.so/elf-buildid-coreclr-bb112233445566778899aabbccddeeff00112233/libmscordaccore.so":
			w.Write([]byte("<html>an answer of something on the way</html>"))
		case "/libmscordaccore.so/elf-buildid-coreclr-cc112233445566778899aabbccddeeff00112233/libmscordaccore.so":
			w.Write(syntheticLibrary(other, []byte("for another processor")))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	// The runtimes as images have them: with a helper library of their own
	// beside, which must not be the one that is used.
	root := t.TempDir()
	runtimeOf := func(first byte, machine elf.Machine) string {
		dir := filepath.Join(root, "usr/share/dotnet", strconv.Itoa(int(first)))
		os.MkdirAll(dir, 0o755)
		id := []byte{first, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33}
		os.WriteFile(filepath.Join(dir, "libcoreclr.so"), syntheticLibrary(machine, id), 0o755)
		os.WriteFile(filepath.Join(dir, "libmscordaccore.so"), syntheticLibrary(machine, []byte("the image's own")), 0o755)
		return filepath.Join(dir, "libcoreclr.so")
	}
	d := Describer{Scratch: t.TempDir(), symbols: server.URL}
	ctx := context.Background()

	for range 2 {
		dir, err := d.dotnetHelper(ctx, runtimeOf(0x00, here))
		if err != nil || dir == "" {
			t.Fatalf("the helper of a runtime that the server knows: %q, %v", dir, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Fatalf("the helper's directory holds %d files", len(entries))
		}
		if content, _ := os.ReadFile(filepath.Join(dir, "libmscordaccore.so")); !bytes.Equal(content, published) {
			t.Fatal("the helper is not the one that the server has")
		}
		if strings.HasPrefix(dir, root) {
			t.Fatal("the helper is in the program's root")
		}
	}
	// A runtime that Microsoft did not build.
	for range 2 {
		if dir, err := d.dotnetHelper(ctx, runtimeOf(0xaa, here)); dir != "" || err != nil {
			t.Fatalf("the helper of a runtime that the server does not know: %q, %v", dir, err)
		}
	}
	if len(asked) != 2 {
		t.Fatalf("the server was asked %d times for two runtimes: %v", len(asked), asked)
	}
	if dir, err := d.dotnetHelper(ctx, runtimeOf(0xbb, here)); dir != "" || err == nil {
		t.Fatalf("an answer that is no library: %q, %v", dir, err)
	}
	if dir, err := d.dotnetHelper(ctx, runtimeOf(0xcc, here)); dir != "" || err == nil {
		t.Fatalf("a library for another processor: %q, %v", dir, err)
	}
	// The core of another processor: its helper is not asked for.
	before := len(asked)
	if dir, err := d.dotnetHelper(ctx, runtimeOf(0x00, other)); dir != "" || err != nil || len(asked) != before {
		t.Fatalf("the runtime of another processor: %q, %v, asked %v", dir, err, asked[before:])
	}
}

// A copy of a core is filled with the pages of the assemblies and libraries
// that the core maps and does not hold, at the addresses they were mapped at.
func TestCoreIsFilledFromItsFiles(t *testing.T) {
	const page = 0x1000
	root := t.TempDir()
	content := func(mark byte, pages int, start string) []byte {
		b := bytes.Repeat([]byte{mark}, pages*page)
		for i := range pages {
			b[i*page+8] = byte(i) // each page tells its number
		}
		copy(b, start)
		return b
	}
	assembly := content('a', 4, "MZ")[:3*page+0x800] // ends within its last page
	library := content('l', 2, "\x7fELF")
	for name, b := range map[string][]byte{"app/shop.dll": assembly, "lib/libcoreclr.so": library, "data/orders.db": content('d', 1, "SQLite")} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
		os.WriteFile(filepath.Join(root, name), b, 0o644)
	}
	// The core's note of its mapped files: the assembly from its second
	// page on, the library, a data file and a file that is gone.
	mappings := []coreMapping{
		{0x10000, 0x13000, 1 * page, "/app/shop.dll"},
		{0x30000, 0x32000, 0, "/lib/libcoreclr.so"},
		{0x40000, 0x41000, 0, "/data/orders.db"},
		{0x50000, 0x51000, 0, "/app/gone.dll"},
	}
	files := binary.LittleEndian.AppendUint64(nil, uint64(len(mappings)))
	files = binary.LittleEndian.AppendUint64(files, page)
	for _, m := range mappings {
		for _, n := range []uint64{m.start, m.end, m.offset / page} {
			files = binary.LittleEndian.AppendUint64(files, n)
		}
	}
	for _, m := range mappings {
		files = append(append(files, m.name...), 0)
	}
	note := binary.LittleEndian.AppendUint32(nil, 5)
	note = binary.LittleEndian.AppendUint32(note, uint32(len(files)))
	note = binary.LittleEndian.AppendUint32(note, 0x46494c45)
	note = append(append(note, "CORE\x00\x00\x00\x00"...), files...)
	for len(note)%4 != 0 {
		note = append(note, 0)
	}
	// And the status of its one thread, which holds the thread's number.
	const statusSize = 336
	note = binary.LittleEndian.AppendUint32(note, 5)
	note = binary.LittleEndian.AppendUint32(note, statusSize)
	note = binary.LittleEndian.AppendUint32(note, 1)
	note = append(note, "CORE\x00\x00\x00\x00"...)
	inNote := len(note) + 32
	note = append(note, make([]byte, statusSize)...)
	binary.LittleEndian.PutUint32(note[inNote:], 5000)
	// Of the assembly the core holds the page that the process changed; the
	// first it names without holding it, as the kernel does, and the third
	// not at all. Of the library it holds the first page, as both do.
	changed := bytes.Repeat([]byte{'c'}, page)
	const segments = 5
	at := uint64(64 + segments*56)
	table := []elf.Prog64{
		{Type: uint32(elf.PT_NOTE), Off: at, Filesz: uint64(len(note))},
		{Type: uint32(elf.PT_LOAD), Off: at + uint64(len(note)), Vaddr: 0x10000, Memsz: page},
		{Type: uint32(elf.PT_LOAD), Off: at + uint64(len(note)), Vaddr: 0x11000, Filesz: page, Memsz: page},
		{Type: uint32(elf.PT_LOAD), Off: at + uint64(len(note)) + page, Vaddr: 0x30000, Filesz: page, Memsz: 2 * page},
		{Type: uint32(elf.PT_LOAD), Off: at + uint64(len(note)) + 2*page, Vaddr: 0x60000, Filesz: page, Memsz: page},
	}
	status := int(at) + inNote // where the thread's number is in the file
	var core bytes.Buffer
	header := elf.Header64{Type: uint16(elf.ET_CORE), Machine: uint16(elf.EM_X86_64), Version: 1, Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: segments}
	copy(header.Ident[:], "\x7fELF\x02\x01\x01")
	binary.Write(&core, binary.LittleEndian, header)
	binary.Write(&core, binary.LittleEndian, table)
	core.Write(note)
	core.Write(changed)
	core.Write(library[:page])
	core.Write(bytes.Repeat([]byte{'h'}, page)) // memory of no file
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "core"), core.Bytes(), 0o600)

	filled := filepath.Join(dir, "filled")
	// The core numbers its thread as the node does; the copy as the container.
	if err := fillCore(filepath.Join(dir, "core"), root, filled, map[int]int{5000: 7}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filled); binary.LittleEndian.Uint32(b[status:]) != 7 {
		t.Fatal("the thread's number in the copy:", binary.LittleEndian.Uint32(b[status:]))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "core")); binary.LittleEndian.Uint32(b[status:]) != 5000 {
		t.Fatal("the core itself was changed")
	}
	file, err := elf.Open(filled)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// memory reads the bytes at an address as a debugger does: from the
	// first segment that holds it.
	memory := func(address uint64, n int) []byte {
		for _, p := range file.Progs {
			if p.Type == elf.PT_LOAD && address >= p.Vaddr && address < p.Vaddr+p.Memsz {
				b := make([]byte, n)
				got, _ := p.ReadAt(b, int64(address-p.Vaddr))
				return b[:got]
			}
		}
		return nil
	}
	for name, c := range map[string]struct {
		address uint64
		want    []byte
	}{
		"a page of the assembly that the core named only": {0x10000, assembly[1*page : 2*page]},
		"the page that the process changed":               {0x11000, changed},
		"a page of the assembly that the core left out":   {0x12000, assembly[3*page:]},
		"past the end of the assembly":                    {0x12800, nil},
		"the library's page that the core held":           {0x30000, library[:page]},
		"the library's page that it did not":              {0x31000, library[page:]},
		"a data file":                                     {0x40000, nil},
		"a file that is gone":                             {0x50000, nil},
		"memory of no file":                               {0x60000, bytes.Repeat([]byte{'h'}, page)},
	} {
		if got := memory(c.address, page); !bytes.Equal(got, c.want) {
			t.Errorf("%s: %d bytes at %#x, starting %q", name, len(got), c.address, got[:min(len(got), 12)])
		}
	}
	if got := coreMappings(file); !slices.Equal(got, mappings) {
		t.Errorf("the filled core names its files as %+v", got)
	}
	before, _ := os.Stat(filepath.Join(dir, "core"))
	after, _ := os.Stat(filled)
	if added := after.Size() - before.Size(); added > 4*page {
		t.Errorf("the filled core is %d bytes larger", added)
	}
}

// The program files of a .NET core hold its managed assemblies and their
// PDBs; those of another core hold no such file.
func TestProgramFilesOfADotnetCore(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"usr/share/dotnet/libcoreclr.so": "\x7fELF runtime", "app/shop.dll": "MZ assembly", "app/shop.pdb": "BSJB lines",
		"app/lib.dll": "MZ assembly without a PDB", "app/appsettings.json": "{}", "app/other.pdb": "BSJB of no mapped assembly",
	} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755)
		os.WriteFile(filepath.Join(root, name), []byte(content), 0o644)
	}
	managed := `{"file":"/app/shop.dll"},{"file":"/app/shop.dll"},{"file":"/app/lib.dll"},{"file":"/app/appsettings.json"},{"file":"/app/gone.dll"}`
	files := Files([]byte(`{"mappings":[{"file":"/usr/share/dotnet/libcoreclr.so"},`+managed+`]}`), root)
	if want := []string{"/usr/share/dotnet/libcoreclr.so", "/app/shop.dll", "/app/shop.pdb", "/app/lib.dll"}; !slices.Equal(files, want) {
		t.Fatal(files)
	}
	var archive bytes.Buffer
	if err := WriteFiles(&archive, root, files); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ExtractFiles(bytes.NewReader(archive.Bytes()), dir, int64(archive.Len())); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "app/shop.pdb")); string(b) != "BSJB lines" {
		t.Fatalf("unpacked %q", b)
	}
	if files := Files([]byte(`{"mappings":[`+managed+`]}`), root); len(files) != 0 {
		t.Fatal("of a core without the .NET runtime:", files)
	}
}

// A synthetic .NET program whose threads wait where the test finds them,
// one of them with an exception that it caught.
const waitingDotnet = `using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace Shop;

public class OrderQueue
{
    private readonly object gate = new();

    [MethodImpl(MethodImplOptions.NoInlining)]
    public void WaitForOrder(int shelf, string customer)
    {
        Program.Waiting.Signal();
        lock (gate) { Monitor.Wait(gate); }
    }
}

public class Billing
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public void Charge(int order)
    {
        try { Fail(order); }
        catch (InvalidOperationException e) { HoldFailure(e); }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Fail(int order) => throw new InvalidOperationException("card declined for synthetic order " + order);

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void HoldFailure(Exception e)
    {
        Program.Waiting.Signal();
        Thread.Sleep(Timeout.Infinite);
    }
}

public static class Program
{
    public static readonly CountdownEvent Waiting = new(2);

    [DllImport("libc")]
    private static extern int prctl(int option, ulong a, ulong b, ulong c, ulong d);

    public static void Main()
    {
        prctl(0x59616d61, ulong.MaxValue, 0, 0, 0); // lets the test's gcore, a sibling, attach
        var queue = new OrderQueue();
        new Thread(() => queue.WaitForOrder(7, "alice")) { IsBackground = true }.Start();
        new Thread(() => new Billing().Charge(7)) { IsBackground = true }.Start();
        Waiting.Wait();
        Console.WriteLine("ready");
        Thread.Sleep(Timeout.Infinite);
    }
}
`

// The project builds for the runtime that the SDK brings.
const waitingDotnetProject = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net$(BundledNETCoreAppTargetFrameworkVersion)</TargetFramework>
    <AssemblyName>shop</AssemblyName>
    <RootNamespace>Shop</RootNamespace>
    <Nullable>enable</Nullable>
    <UseAppHost>false</UseAppHost>
  </PropertyGroup>
</Project>
`

// The core of a .NET program is described with the runtime's threads as
// .NET sees them: methods, source lines and the exception a thread holds.
// The helper library comes from the symbol server only, and where no server
// may be asked the description stands without.
func TestDotnetStacksOfACore(t *testing.T) {
	dotnet := DotnetDir
	if set := os.Getenv("ASSERVAT_DOTNET"); set != "" {
		dotnet = set
	}
	if _, err := os.Stat(filepath.Join(dotnet, "dotnet")); err != nil {
		t.Skipf("dotnet-dump is not installed at %s", dotnet)
	}
	for _, tool := range []string{"dotnet", "gcore", "gdb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Program.cs"), []byte(waitingDotnet), 0o644)
	os.WriteFile(filepath.Join(dir, "shop.csproj"), []byte(waitingDotnetProject), 0o644)
	env := append(os.Environ(), "HOME="+dir, "DOTNET_CLI_HOME="+dir, "DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1")
	build := exec.Command("dotnet", "build", "-c", "Release", "-o", filepath.Join(dir, "out"))
	build.Dir, build.Env = dir, env
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("the .NET SDK does not build here: %v: %s", err, tail(out))
	}
	cmd := exec.Command("dotnet", filepath.Join(dir, "out", "shop.dll"))
	cmd.Env = env
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("program said %q: %v", line, err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if out, err := exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
		t.Skipf("gcore cannot attach here: %v: %s", err, tail(out))
	}
	// The test's symbol server has the helper library of the runtime that
	// runs the program, as Microsoft's has those of the runtimes it built.
	maps, _ := os.ReadFile("/proc/" + pid + "/maps")
	mapped := regexp.MustCompile(`(?m)\S+/libcoreclr\.so$`).FindString(string(maps))
	if mapped == "" {
		t.Fatal("the program maps no libcoreclr.so")
	}
	var mu sync.Mutex
	asked := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/symbols/libmscordaccore.so/elf-buildid-coreclr-") {
			http.NotFound(w, r) // gdb's asking for debug information
			return
		}
		mu.Lock()
		asked++
		mu.Unlock()
		helper, err := os.Open(filepath.Join(filepath.Dir(mapped), "libmscordaccore.so"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer helper.Close()
		io.Copy(w, helper)
	}))
	defer server.Close()
	core, root := filepath.Join(dir, "core."+pid), "/proc/"+pid+"/root"

	// Without servers to ask, the helper is not fetched.
	d := Describer{Scratch: t.TempDir(), DotnetDir: dotnet, symbols: server.URL + "/symbols"}
	data, err := d.Describe(context.Background(), core, root)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Threads       []json.RawMessage
		RuntimeStacks []struct {
			Runtime, Title, Version string
			Threads                 []struct {
				Status         string
				ThreadSystemID int
				Frames         []struct {
					Function, File string
					Line           int
				}
			}
		}
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Threads) == 0 || len(report.RuntimeStacks) != 0 || asked != 0 {
		t.Fatalf("without servers: %d threads of gdb, runtime stacks %+v, the symbol server asked %d times", len(report.Threads), report.RuntimeStacks, asked)
	}

	d.DebuginfodURLs = server.URL + "/debuginfod"
	if data, err = d.Describe(context.Background(), core, root); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.RuntimeStacks) != 1 || report.RuntimeStacks[0].Runtime != "dotnet" || report.RuntimeStacks[0].Version == "" || asked != 1 {
		t.Fatalf("runtime stacks: %+v, the symbol server asked %d times", report.RuntimeStacks, asked)
	}
	found := map[string]bool{}
	for _, thread := range report.RuntimeStacks[0].Threads {
		for _, f := range thread.Frames {
			found[f.Function] = true
			switch f.Function {
			case "Shop.OrderQueue.WaitForOrder(Int32, System.String)":
				if filepath.Base(f.File) != "Program.cs" || f.Line == 0 || thread.ThreadSystemID == 0 || thread.Status != "" {
					t.Errorf("WaitForOrder: %s line %d, thread %d, status %q", f.File, f.Line, thread.ThreadSystemID, thread.Status)
				}
			case "Shop.Billing.Charge(Int32)":
				if thread.Status != "holds System.InvalidOperationException: card declined for synthetic order 7" {
					t.Errorf("Charge: status %q", thread.Status)
				}
			}
		}
	}
	for _, name := range []string{"Shop.OrderQueue.WaitForOrder(Int32, System.String)", "Shop.Billing.Charge(Int32)", "Shop.Program.Main()"} {
		if !found[name] {
			t.Errorf("no thread in %s", name)
		}
	}
	// The copy of the core is gone; the helper stays for the next core.
	entries, _ := os.ReadDir(d.Scratch)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "dotnet-") && entry.Name() != "dotnet-helpers" {
			t.Errorf("left in the scratch directory: %s", entry.Name())
		}
	}
}

// A helper library that was built for musl is told by the C library that
// it asks for: it loads only into the tool that runs on musl.
func TestHelperForMuslIsTold(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is not installed")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "empty.c"), []byte("int helper;\n"), 0o644)
	build := func(args ...string) {
		cmd := exec.Command("gcc", append([]string{"-shared", "-nostdlib", "-fPIC"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("gcc cannot build the test libraries here: %v: %s", err, out)
		}
	}
	// A library that stands for musl's C library, by its name.
	build("-Wl,-soname,libc.musl-x86_64.so.1", "-o", "libc.musl-x86_64.so.1", "empty.c")
	// Asked for though nothing of it is used, which some linkers leave out.
	build("-o", "for-musl.so", "empty.c", "-L.", "-Wl,--no-as-needed", "-l:libc.musl-x86_64.so.1")
	build("-o", "for-glibc.so", "empty.c")
	if !forMusl(filepath.Join(dir, "for-musl.so")) || forMusl(filepath.Join(dir, "for-glibc.so")) || forMusl(filepath.Join(dir, "none.so")) {
		t.Fatal("for musl:", forMusl(filepath.Join(dir, "for-musl.so")), forMusl(filepath.Join(dir, "for-glibc.so")), forMusl(filepath.Join(dir, "none.so")))
	}
}

// Microsoft's symbol server takes its time over a helper that it is rarely
// asked for: it is waited for longer than a server of debug packages is.
func TestDotnetHelperIsWaitedForLonger(t *testing.T) {
	here, known := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if !known {
		t.Skip("no helper libraries for this processor")
	}
	const wait = 50 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(6 * wait) // longer than both attempts at a debug package would wait
		w.Write(syntheticLibrary(here, []byte("the helper, late")))
	}))
	defer server.Close()
	runtimeFile := filepath.Join(t.TempDir(), "libcoreclr.so")
	os.WriteFile(runtimeFile, syntheticLibrary(here, []byte{0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33}), 0o755)
	dir, err := Describer{Scratch: t.TempDir(), symbols: server.URL, wait: wait}.dotnetHelper(context.Background(), runtimeFile)
	if err != nil || dir == "" {
		t.Fatalf("a helper that the server took its time over: %q, %v", dir, err)
	}
}

// Microsoft's symbol server says 404 for a helper that it does not have. It
// was seen to say 403 for one that it has, and a helper taken as missing is
// not asked for again for a week.
func TestDotnetHelperThatIsForbiddenIsNotTakenAsMissing(t *testing.T) {
	here, known := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if !known {
		t.Skip("no helper libraries for this processor")
	}
	for _, test := range []struct {
		name   string
		forbid int32
	}{{"once", 1}, {"twice", 2}} {
		t.Run(test.name, func(t *testing.T) {
			var asked atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if asked.Add(1) <= test.forbid {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Write(syntheticLibrary(here, []byte("the helper")))
			}))
			defer server.Close()
			runtimeFile := filepath.Join(t.TempDir(), "libcoreclr.so")
			os.WriteFile(runtimeFile, syntheticLibrary(here, []byte{0xee, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33}), 0o755)
			d := Describer{Scratch: t.TempDir(), symbols: server.URL}
			dir, err := d.dotnetHelper(context.Background(), runtimeFile)
			if test.forbid == 1 {
				if err != nil || dir == "" {
					t.Fatalf("a helper that the server forbade once: %q, %v", dir, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a helper that the server forbade twice is taken as one it does not have: %q", dir)
			}
			// The server is asked again the next time, not after a week.
			if dir, err := d.dotnetHelper(context.Background(), runtimeFile); err != nil || dir == "" {
				t.Fatalf("the helper was not asked for again: %q, %v", dir, err)
			}
		})
	}
}
