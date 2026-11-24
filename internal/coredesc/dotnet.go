package coredesc

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// A core of a .NET program shows gdb the runtime: threads in libcoreclr.so
// and in code that the runtime compiled, which has no symbols. What the
// program did is in the runtime's memory. dotnet-dump (Microsoft, MIT)
// reads it: the managed threads with their methods, source lines where the
// program ships its PDBs, and the exception a thread holds.
//
// dotnet-dump reads the runtime's memory with the runtime's own helper
// library (the DAC, libmscordaccore.so), which is built with each runtime
// and loaded into the tool: its code runs in the agent and in the hub. So
// it is never taken from the workload's image. Microsoft's symbol server
// has the helper of every runtime that Microsoft built, under the build ID
// of that runtime's libcoreclr.so; it is fetched from there, and a runtime
// that the server does not know is described without. The managed
// assemblies and PDBs of the image are data and are read.

// DotnetDir is the directory in Asservat's hub image with a .NET runtime
// (dotnet) and dotnet-dump (dump/dotnet-dump.dll); the same name with
// "-musl" has both for the cores of runtimes built for musl. No image of a .NET
// program has its runtime there, so the tool finds no helper library at the
// path that a core names. Where it is not there, .NET stacks are left to a
// describer that has it.
const DotnetDir = "/opt/asservat-dotnet"

// microsoftSymbols is Microsoft's public symbol server. It answers with a
// redirect to the file in Azure's blob storage (*.blob.core.windows.net).
// Neither offers a checksum or signature of an ELF file, so the download is
// trusted as far as HTTPS to these hosts is.
const microsoftSymbols = "https://msdl.microsoft.com/download/symbols"

const (
	coreclr = "libcoreclr.so"
	dac     = "libmscordaccore.so"
)

var (
	// A thread in the tool's list: its number in the debugger, the runtime's
	// ID, the system's in hexadecimal, then nine columns of the runtime's
	// state, then what the thread is and the exception it holds.
	dotnetThread = regexp.MustCompile(`^\s*(?:\d+|XXXX)\s+(\d+)\s+([0-9a-f]+)\s+[0-9A-Fa-f]{8,}\s+[0-9a-f]+\s+\S+\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+-?\d+\s+\S+ ?(.*)$`)
	// What a thread is: "(Finalizer)", "(Threadpool Worker)".
	dotnetKind = regexp.MustCompile(`^\(([^)]*)\) ?`)
	// The exception a thread holds: its type and its address.
	dotnetHeld = regexp.MustCompile(`^(\S+) ([0-9a-f]{8,})\b`)
	// A frame: the stack pointer, the instruction, the method.
	dotnetFrame = regexp.MustCompile(`^[0-9A-Fa-f]{8,} ([0-9A-Fa-f]{8,}) (.*)$`)
	// A mark that the runtime left on the stack, with the method it is
	// for, if any: "[HelperMethodFrame: 00007e5d55fbbe08] System.Threading.Thread.SleepInternal(Int32)".
	dotnetMark = regexp.MustCompile(`^\[\w+: [0-9a-f]+\] ?(.*)$`)
	// A method with its source line: "Shop.Billing.Charge(System.Decimal) [/src/Program.cs @ 24]".
	dotnetLine = regexp.MustCompile(`^(.*) \[(.+) @ (\d+)\]$`)
	// A runtime's version as the directory of its files is named: 8.0.34.
	dotnetVersion = regexp.MustCompile(`^\d+\.\d+\.\d+[A-Za-z0-9.+-]*$`)
)

type dotnetThreadStack struct {
	ID             int       `json:"id"`
	Name           string    `json:"name"`
	Status         string    `json:"status"`
	Current        bool      `json:"current"`
	ThreadSystemID int       `json:"threadSystemId"`
	Frames         []goFrame `json:"frames"`
	Cut            bool      `json:"cut"`
	// held is the address of the exception that the thread holds.
	held string
}

// describeDotnet adds the managed stacks of a .NET program to gdb's report
// of its core. The report of another program returns unchanged, and so
// does that of a .NET program where no server may be asked or where
// Microsoft does not have the runtime's helper. Where the tool is not
// installed, the report awaits a describer that has it.
func (d Describer) describeDotnet(ctx context.Context, report []byte, core, root string) ([]byte, error) {
	dir := cmp.Or(d.DotnetDir, DotnetDir)
	var fields struct{ Mappings []struct{ File string } }
	if err := json.Unmarshal(report, &fields); err != nil {
		return nil, err
	}
	var mapped []string
	for _, m := range fields.Mappings {
		mapped = append(mapped, m.File)
	}
	at := slices.IndexFunc(mapped, isCoreCLR)
	if at < 0 || root == "" {
		return report, nil
	}
	if !d.has(runtimeDotnet) {
		return await(report, runtimeDotnet)
	}
	if d.DebuginfodURLs == "" {
		return report, nil
	}
	runtimeFile, _ := resolve(root, strings.TrimSuffix(mapped[at], " (deleted)"))
	if runtimeFile == "" {
		return report, nil
	}
	helper, err := d.dotnetHelper(ctx, filepath.Join(root, runtimeFile))
	if helper == "" || err != nil {
		return report, err
	}
	// A runtime built for musl, as in Alpine images, has a helper library
	// for musl, which a tool that runs on glibc cannot load: the hub's
	// image has the tool's runtime a second time, built for musl.
	musl := forMusl(filepath.Join(helper, dac))
	if musl {
		dir += "-musl"
		if _, err := os.Stat(filepath.Join(dir, "dotnet")); err != nil {
			slog.Info("no .NET stacks: the runtime is built for musl (an Alpine image), and no dotnet-dump for musl is installed", "libcoreclr", runtimeFile, "at", dir)
			return report, nil
		}
	}
	work, err := os.MkdirTemp(d.Scratch, "dotnet-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	// The tool is told no directory of the program's: where it does not
	// find the helper library it looks for one in the directories it knows.
	// It gets the PDBs as links in a directory of their own.
	pdbs := filepath.Join(work, "pdb")
	if err := os.Mkdir(pdbs, 0o700); err != nil {
		return nil, err
	}
	for _, name := range dotnetFiles(mapped, root) {
		if file, _ := resolve(root, name); pathpkg.Ext(name) == ".pdb" && file != "" {
			os.Symlink(filepath.Join(root, file), filepath.Join(pdbs, pathpkg.Base(name))) // of two with one name, the first
		}
	}
	filled := filepath.Join(work, "core")
	if err := fillCore(core, root, filled, d.ThreadIDs); err != nil {
		return nil, err
	}
	ctx, end := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "dotnet"), filepath.Join(dir, "dump", "dotnet-dump.dll"), "analyze", filled)
	// The runtime and the tool write where HOME and TMPDIR say.
	cmd.Env = append(os.Environ(), "HOME="+work, "TMPDIR="+work, "DOTNET_CLI_HOME="+work)
	if musl {
		// Alpine's C++ libraries, which the runtime for musl asks for. It
		// finds no ICU in this image and needs none: the tool reads no
		// text that depends on a language.
		cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+filepath.Join(dir, "lib"), "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1")
	}
	cmd.Dir = work
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		end()
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		end()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		end()
		return nil, err
	}
	// Every answer is read before the next command: there is nothing left
	// for the tool to say when it is ended.
	defer func() {
		end()
		cmd.Wait()
	}()
	answers := bufio.NewReader(out)
	// The tool ends each answer, and what it says when it starts, with a
	// line of its own.
	ask := func(command string) (string, error) {
		if command != "" {
			if _, err := fmt.Fprintln(in, command); err != nil {
				return "", fmt.Errorf("dotnet-dump: %s: %w: %s", command, err, tail(stderr.Bytes()))
			}
		}
		var answer strings.Builder
		for {
			line, err := answers.ReadString('\n')
			switch strings.TrimSpace(line) {
			case "<END_COMMAND_OUTPUT>":
				return answer.String(), nil
			case "<END_COMMAND_ERROR>":
				return "", fmt.Errorf("dotnet-dump: %s: %s", command, tail([]byte(answer.String())))
			}
			if err != nil {
				return "", fmt.Errorf("dotnet-dump: %s: %w: %s", command, err, tail(stderr.Bytes()))
			}
			answer.WriteString(line)
		}
	}
	var threads, stacks, version string
	// Its own asking of Microsoft's symbol server is turned off first: it
	// would send what identifies every module of the core.
	for _, step := range []struct {
		command string
		answer  *string
	}{{"", nil}, {"setsymbolserver -disable", nil}, {"setclrpath " + helper, nil}, {"setsymbolserver -directory " + pdbs, nil},
		{"eeversion", &version}, {"clrthreads", &threads}, {"clrstack -all", &stacks}} {
		answer, err := ask(step.command)
		if err != nil {
			return nil, err
		}
		if step.answer != nil {
			*step.answer = answer
		}
	}
	list := dotnetThreads(threads)
	if len(list) == 0 {
		return nil, fmt.Errorf("dotnet-dump: no threads: %s", tail([]byte(threads)))
	}
	frames, cut := dotnetStacks(stacks)
	for i := range list {
		thread := &list[i]
		thread.Frames, thread.Cut = frames[thread.ThreadSystemID], cut[thread.ThreadSystemID]
		if thread.Frames == nil {
			thread.Frames = []goFrame{}
		}
		// As gdb names the thread: by its number on the node.
		thread.ThreadSystemID = d.onNode(thread.ThreadSystemID)
		if thread.held == "" {
			continue
		}
		// Without the tool's account of the exception its type stands alone.
		if answer, err := ask("pe -nested " + thread.held); err == nil {
			if message := dotnetMessage(answer); message != "" {
				thread.Status += ": " + message
			}
		}
	}
	// The directory of a runtime's files is named by its version; one that
	// came with its program says a version of its file, as 8.0.3426.52217.
	if named := pathpkg.Base(pathpkg.Dir(runtimeFile)); dotnetVersion.MatchString(named) {
		version = named
	} else {
		lines := strings.Split(version, "\n")
		version = ""
		if at := slices.IndexFunc(lines, func(line string) bool { return dotnetVersion.MatchString(strings.TrimSpace(line)) }); at >= 0 {
			version = strings.TrimSpace(lines[at])
		}
	}
	described, err := json.Marshal(list)
	if err != nil {
		return nil, err
	}
	return addRuntimeStack(report, runtimeStack{Runtime: "dotnet", Title: ".NET threads", Version: version, Threads: described})
}

// dotnetThreads reads the tool's list of the runtime's threads (clrthreads).
// A thread that has ended has no thread of the system and is left out.
func dotnetThreads(answer string) []dotnetThreadStack {
	var threads []dotnetThreadStack
	for _, line := range strings.Split(answer, "\n") {
		m := dotnetThread.FindStringSubmatch(strings.TrimRight(line, " \r"))
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		system, _ := strconv.ParseInt(m[2], 16, 64)
		if system == 0 {
			continue
		}
		thread := dotnetThreadStack{ID: id, ThreadSystemID: int(system)}
		rest := m[3]
		// What the runtime uses a thread for stands for its name: the tool
		// does not tell the name that the program gave.
		var kinds []string
		for kind := dotnetKind.FindStringSubmatch(rest); kind != nil; kind = dotnetKind.FindStringSubmatch(rest) {
			kinds, rest = append(kinds, kind[1]), rest[len(kind[0]):]
		}
		thread.Name = strings.Join(kinds, ", ")
		if held := dotnetHeld.FindStringSubmatch(rest); held != nil {
			thread.Status, thread.held = "holds "+held[1], held[2]
		}
		threads = append(threads, thread)
	}
	return threads
}

// dotnetStacks reads the tool's stacks of all threads (clrstack -all), by
// the system's thread ID: the frames innermost first, at most maxFrames,
// and whether there were more. The marks that the runtime leaves on a
// stack where managed code calls into the runtime or out of it
// ([InlinedCallFrame], [DebuggerU2MCatchHandlerFrame]) are no calls of the
// program and are left out; where a mark names the method that the runtime
// works for ([HelperMethodFrame] Monitor.ObjWait), the method stays as a
// frame.
func dotnetStacks(answer string) (map[int][]goFrame, map[int]bool) {
	frames, cut := map[int][]goFrame{}, map[int]bool{}
	thread := 0
	for _, line := range strings.Split(answer, "\n") {
		line = strings.TrimRight(line, " \r")
		if id, ok := strings.CutPrefix(line, "OS Thread Id: 0x"); ok {
			id, _, _ = strings.Cut(id, " ")
			system, _ := strconv.ParseInt(id, 16, 64)
			thread = int(system)
			continue
		}
		m := dotnetFrame.FindStringSubmatch(line)
		if m == nil || thread == 0 {
			continue
		}
		site := m[2]
		if mark := dotnetMark.FindStringSubmatch(site); mark != nil {
			site = mark[1]
		}
		if site == "" {
			continue
		}
		if len(frames[thread]) == maxFrames {
			cut[thread] = true
			continue
		}
		frame := goFrame{Level: len(frames[thread]), PC: "0x" + strings.TrimLeft(strings.ToLower(m[1]), "0"), Function: site, Arguments: []goVariable{}, Locals: []goVariable{}}
		if at := dotnetLine.FindStringSubmatch(site); at != nil {
			frame.Function, frame.File = at[1], at[2]
			frame.Line, _ = strconv.Atoi(at[3])
		}
		frames[thread] = append(frames[thread], frame)
	}
	return frames, cut
}

// dotnetMessage reads the message of an exception from the tool's account
// of it (pe), cut like a value.
func dotnetMessage(answer string) string {
	for _, line := range strings.Split(answer, "\n") {
		if message, ok := strings.CutPrefix(line, "Message:"); ok {
			message = strings.TrimSpace(message)
			if message == "<none>" {
				return ""
			}
			if text := []rune(message); len(text) > maxValue {
				message = string(text[:maxValue]) + "…"
			}
			return message
		}
	}
	return ""
}

// dotnetHelper returns the directory that holds the helper library of the
// runtime whose libcoreclr.so is given, and nothing else: downloaded from
// Microsoft's symbol server, which is sent the runtime's build ID, and kept
// in the scratch directory until unused for a week. It is empty for a
// runtime that Microsoft's server does not have, as those that
// distributions build from source, and for one of another processor than
// this one: the helper that reads such a core is another file.
func (d Describer) dotnetHelper(ctx context.Context, runtimeFile string) (string, error) {
	file, err := elf.Open(runtimeFile)
	if err != nil {
		return "", nil
	}
	id, machine := buildID(file), file.Machine
	file.Close()
	here := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if id == "" || machine != here {
		return "", nil
	}
	server := d.symbols
	if server == "" {
		server = microsoftSymbols
	}
	f := d.fetcher(ctx, "dotnet-helpers")
	if err := os.MkdirAll(f.cache, 0o700); err != nil {
		return "", err
	}
	f.sweep()
	dir := filepath.Join(f.cache, id)
	if _, err := os.Stat(dir); err == nil {
		// An empty directory is of a helper that was not there. It keeps
		// its age, so that the server is asked again after a week.
		if _, err := os.Stat(filepath.Join(dir, dac)); err != nil {
			return "", nil
		}
		now := time.Now()
		os.Chtimes(dir, now, now)
		return dir, nil
	}
	fetched, err := os.MkdirTemp(f.cache, "fetch-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(fetched)
	// The server's name for the helper of a runtime: by the build ID of
	// the runtime's libcoreclr.so (the "coreclr" kind of key of
	// Microsoft.SymbolStore).
	address := server + "/" + dac + "/elf-buildid-coreclr-" + id + "/" + dac
	body, err := f.get(address)
	if err == errNotPublished {
		slog.Info("no .NET stacks: Microsoft's symbol server does not have the helper library of this runtime", "libcoreclr", runtimeFile, "buildID", id)
	} else if err != nil {
		return "", err
	} else {
		path := filepath.Join(fetched, dac)
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
		if err == nil {
			_, err = io.Copy(out, body)
			if e := out.Close(); err == nil {
				err = e
			}
		}
		body.Close()
		if err != nil {
			return "", fmt.Errorf("%s: %w", address, err)
		}
		// What came must be a library for this processor.
		library, err := elf.Open(path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", address, err)
		}
		library.Close()
		if library.Type != elf.ET_DYN || library.Machine != here {
			return "", fmt.Errorf("%s: not a library for this processor", address)
		}
	}
	// Another description may have fetched the same meanwhile.
	if err := os.Rename(fetched, dir); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, dac)); err != nil {
		return "", nil
	}
	return dir, nil
}

// forMusl tells whether a library is built for musl, the C library of
// Alpine images, by the C library that it asks for.
func forMusl(path string) bool {
	library, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer library.Close()
	needs, _ := library.ImportedLibraries()
	return slices.ContainsFunc(needs, func(name string) bool { return strings.HasPrefix(name, "libc.musl") })
}

// fillCore writes a copy of the core that also holds the pages of the
// managed assemblies and of the programs and libraries that the core maps
// and does not hold. The kernel and gcore leave out the pages of a file
// that the process did not change: a debugger reads them from the file.
// The .NET tools read a memory image only. Without the assemblies'
// metadata they walk no stack, and without the unwind tables of the
// runtime's libraries a stack ends at the first call into the runtime. The
// pages are appended from the files under root, as further segments.
//
// The copy takes the disk space of one more core in the scratch directory
// while the core is described, less where the filesystem shares the blocks
// of a copy (as Btrfs does), plus what is appended: about 100 MiB for an
// ASP.NET program. For a core of 64-bit little-endian machines.
func fillCore(core, root, filled string, ids map[int]int) error {
	in, err := os.Open(core)
	if err != nil {
		return err
	}
	defer in.Close()
	file, err := elf.NewFile(in)
	if err != nil {
		return err
	}
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB {
		return errors.New("not a core of a 64-bit little-endian machine")
	}
	out, err := os.OpenFile(filled, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	// Between two files the kernel copies, and shares the blocks where the
	// filesystem can (copy_file_range).
	end, err := io.Copy(out, in)
	if err != nil {
		return err
	}
	// The runtime knows its threads by their numbers in the container.
	if len(ids) > 0 {
		if err := renumberThreads(out, file, ids); err != nil {
			return err
		}
	}
	// The segments that hold memory, and the other ones as they are. A
	// segment that says it is larger in memory than in the file would hide
	// what is appended for the rest of it.
	var held, others []elf.Prog64
	for _, p := range file.Progs {
		segment := elf.Prog64{Type: uint32(p.Type), Flags: uint32(p.Flags), Off: p.Off, Vaddr: p.Vaddr, Paddr: p.Paddr, Filesz: p.Filesz, Memsz: p.Memsz, Align: p.Align}
		if p.Type != elf.PT_LOAD {
			others = append(others, segment)
		} else if p.Filesz > 0 {
			segment.Memsz = p.Filesz
			held = append(held, segment)
		}
	}
	slices.SortFunc(held, func(a, b elf.Prog64) int { return cmp.Compare(a.Vaddr, b.Vaddr) })
	var added []elf.Prog64
	sources := map[string]*os.File{}
	defer func() {
		for _, source := range sources {
			if source != nil {
				source.Close()
			}
		}
	}()
	for _, m := range coreMappings(file) {
		source, seen := sources[m.name]
		if !seen {
			if path, _ := resolve(root, strings.TrimSuffix(m.name, " (deleted)")); path != "" && (isPE(filepath.Join(root, path)) || isELF(filepath.Join(root, path))) {
				source, _ = os.Open(filepath.Join(root, path))
			}
			sources[m.name] = source
		}
		if source == nil {
			continue
		}
		// The parts of the mapping that no segment holds.
		at := m.start
		gap := func(from, to uint64) error {
			if from >= to {
				return nil
			}
			n, err := io.Copy(out, io.NewSectionReader(source, int64(m.offset+from-m.start), int64(to-from)))
			if n > 0 {
				added = append(added, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R), Off: uint64(end), Vaddr: from, Filesz: uint64(n), Memsz: uint64(n), Align: 1})
				end += n
			}
			return err
		}
		for _, segment := range held {
			if segment.Vaddr+segment.Filesz <= at || segment.Vaddr >= m.end {
				continue
			}
			if err := gap(at, segment.Vaddr); err != nil {
				return err
			}
			at = max(at, segment.Vaddr+segment.Filesz)
		}
		if err := gap(at, m.end); err != nil {
			return err
		}
	}
	held = append(held, added...)
	slices.SortFunc(held, func(a, b elf.Prog64) int { return cmp.Compare(a.Vaddr, b.Vaddr) })
	table := append(others, held...)
	// The file's header counts its segments in 16 bits, of which the last
	// number says that the count is elsewhere.
	if len(table) >= 0xffff {
		return fmt.Errorf("%d segments are more than a core's header counts", len(table))
	}
	// The new table of segments at the end, and the header to name it.
	if err := binary.Write(out, binary.LittleEndian, table); err != nil {
		return err
	}
	header := make([]byte, 8)
	binary.LittleEndian.PutUint64(header, uint64(end))
	if _, err := out.WriteAt(header, 0x20); err != nil { // e_phoff
		return err
	}
	binary.LittleEndian.PutUint16(header, uint16(len(table)))
	if _, err := out.WriteAt(header[:2], 0x38); err != nil { // e_phnum
		return err
	}
	return out.Close()
}

// isPE tells whether the path is a regular file that starts as a managed
// assembly does: as a program of Windows.
func isPE(path string) bool { return startsWith(path, "MZ") }

// isCoreCLR tells whether a mapped file is the .NET runtime.
func isCoreCLR(name string) bool {
	return pathpkg.Base(strings.TrimSuffix(name, " (deleted)")) == coreclr
}

// dotnetFiles lists what describing a .NET core takes besides the programs
// and libraries that it maps: the managed assemblies that it maps, and the
// PDB next to each, which names the source lines of its methods. In a
// core's program files they let the hub describe the core again as the
// agent did, and take some 28 MiB there for an ASP.NET program. The helper
// library is not among them: the hub fetches it as the agent did. For
// another core there are none.
func dotnetFiles(mapped []string, root string) []string {
	if !slices.ContainsFunc(mapped, isCoreCLR) {
		return nil
	}
	var files []string
	seen := map[string]bool{}
	for _, name := range mapped {
		name = strings.TrimSuffix(name, " (deleted)")
		if seen[name] || !strings.HasPrefix(name, "/") {
			continue
		}
		seen[name] = true
		if file, _ := resolve(root, name); file == "" || !isPE(filepath.Join(root, file)) {
			continue
		}
		files = append(files, name)
		pdb := strings.TrimSuffix(name, pathpkg.Ext(name)) + ".pdb"
		if file, _ := resolve(root, pdb); file != "" && !seen[pdb] {
			seen[pdb] = true
			files = append(files, pdb)
		}
	}
	return files
}
