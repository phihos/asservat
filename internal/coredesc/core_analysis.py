# Run by gdb for a core file: writes what a debugger shows first, as JSON.
# ASSERVAT_CORE names the core, ASSERVAT_ROOT the root directory in which the
# program's executable and libraries are found (may be empty), ASSERVAT_OUT
# the file to write.
import json
import os
import re
import struct

import gdb
import gdb.unwinder

CORE, ROOT, OUT = os.environ["ASSERVAT_CORE"], os.environ.get("ASSERVAT_ROOT", ""), os.environ["ASSERVAT_OUT"]
# A runaway recursion repeats the same frames until the stack ends; the
# innermost frames show it. Deeper stacks are cut and marked.
MAX_FRAMES = 256
# Values are shown as a debugger's variables pane shows them: one line each.
MAX_VALUE = 200


def run(command):
    try:
        return gdb.execute(command, to_string=True)
    except gdb.error:
        return ""


def text(value):
    try:
        s = value.format_string(max_elements=16, max_depth=2)
    except Exception as e:  # unreadable memory, optimized out
        s = "<%s>" % e
    return s if len(s) <= MAX_VALUE else s[:MAX_VALUE] + "…"


def register(value):
    """A register as debuggers show it: in hexadecimal, flags by name."""
    try:
        if value.type.strip_typedefs().code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_PTR):
            return "0x%016x" % (int(value) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        pass
    return text(value)


def variables(frame):
    """Arguments and locals of a frame, if the program has debug information."""
    found = {"arguments": [], "locals": []}
    try:
        block = frame.block()
    except RuntimeError:
        return found
    seen = set()
    while block and not block.is_global and not block.is_static:
        for symbol in block:
            if not (symbol.is_argument or symbol.is_variable) or symbol.name in seen:
                continue
            seen.add(symbol.name)
            try:
                value = text(symbol.value(frame))
            except Exception as e:
                value = "<%s>" % e
            found["arguments" if symbol.is_argument else "locals"].append({"name": symbol.name, "type": str(symbol.type), "value": value})
        if block.function:
            break
        block = block.superblock
    return found


# gdb walks a stack by the unwind tables of each function on it. Some
# libraries carry none: musl, the C library of Alpine images, is built
# without them and without frame pointers. A thread that waits in such a
# library, as most threads of a core do, then ends there for gdb, and the
# program's own functions above it stay unseen. But the way out is on the
# stack: every caller left its return address there. For a frame in a
# module without unwind tables, the unwinder below takes the first word
# above the stack pointer that is the address after a call instruction for
# the caller's, and gdb walks on from there by the caller's own tables.
# A frame found so is marked: it is a reading of the stack, not a proof.
WORD = struct.Struct("<Q")
# How far above a frame's stack pointer its return address is looked for:
# the size of a large frame. Beyond it lies other frames' data, where an old
# return address may linger.
SCAN = 64 << 10
KEPT = {"x86-64": ["rbp", "rbx", "r12", "r13", "r14", "r15"], "aarch64": ["x%d" % n for n in range(19, 30)]}
tables = {}   # by file name: whether the module carries unwind tables
scanned = set()  # the stack pointers of the frames that were found by scanning


def has_tables(objfile):
    """Whether the module has unwind tables: .debug_frame, or an .eh_frame
    that is not tiny beside the code, in the file or in its debug file.
    Tables take some 5 % of the code's size; musl's .eh_frame holds 132
    bytes for 600 KiB of code, for its few functions in assembly."""
    name = objfile.filename or ""
    if name not in tables:
        found = False
        try:
            with open(name[len("target:"):] if name.startswith("target:") else name, "rb") as f:
                header = f.read(64)
                shoff, = struct.unpack_from("<Q", header, 0x28)
                shentsize, shnum, shstrndx = struct.unpack_from("<HHH", header, 0x3A)
                f.seek(shoff)
                sections = [struct.unpack_from("<IIQQQQ", f.read(shentsize)) for _ in range(shnum)]
                f.seek(sections[shstrndx][4])
                names = f.read(sections[shstrndx][5])
                sizes = {names[section[0]:names.index(b"\0", section[0])]: section[5] for section in sections}
                # An .eh_frame of up to 64 bytes holds no more than one entry and its end.
                found = sizes.get(b".debug_frame", 0) > 0 or sizes.get(b".eh_frame", 0) > 64 and sizes.get(b".eh_frame", 0) * 256 > sizes.get(b".text", 0)
        except (OSError, struct.error, ValueError, IndexError):
            found = True  # what cannot be read is left to gdb
        tables[name] = found
    return tables[name] or any(has_tables(o) for o in gdb.objfiles() if o.owner == objfile)


def after_call(inferior, address, machine):
    """Whether the instruction before the address is a call."""
    try:
        before = bytes(inferior.read_memory(address - 8, 8))
    except (gdb.MemoryError, gdb.error):
        return False
    if "aarch64" in machine:
        word, = struct.unpack_from("<I", before, 4)
        return word & 0xFC000000 == 0x94000000 or word & 0xFFFFFC1F == 0xD63F0000  # bl, blr
    # x86-64: call rel32, or an indirect call (FF /2) of 2 to 7 bytes.
    return before[3] == 0xE8 or any(before[8 - n] == 0xFF and (before[9 - n] >> 3) & 7 == 2 for n in (2, 3, 4, 6, 7))


class ScanUnwinder(gdb.unwinder.Unwinder):
    def __init__(self):
        super().__init__("asservat-scan")

    def __call__(self, pending):
        machine = pending.architecture().name()
        if "x86-64" not in machine and "aarch64" not in machine:
            return None
        try:
            pc, sp = int(pending.read_register("pc")), int(pending.read_register("sp"))
            space = gdb.current_progspace()
            module = space.objfile_for_address(pc)
            if module is None or has_tables(module):
                return None
            inferior = gdb.selected_inferior()
            stack = bytes(inferior.read_memory(sp, SCAN))
        except (gdb.MemoryError, gdb.error):
            try:
                stack = bytes(inferior.read_memory(sp, 4096 - sp % 4096))  # to the end of the stack's last page
            except (gdb.MemoryError, gdb.error, UnboundLocalError):
                return None
        for at in range(0, len(stack) - 7, 8):
            caller, = WORD.unpack_from(stack, at)
            if caller > 0x1000 and space.objfile_for_address(caller) is not None and after_call(inferior, caller, machine):
                unwound = pending.create_unwind_info(gdb.unwinder.FrameId(sp + at + 8, pc))
                kind = pending.read_register("pc").type
                unwound.add_saved_register("pc", gdb.Value(caller).cast(kind))
                unwound.add_saved_register("sp", gdb.Value(sp + at + 8).cast(pending.read_register("sp").type))
                # The registers that a function must hand back as it got
                # them are taken as unchanged: where this one saved them is
                # not known. A caller that needs one it changed is walked
                # wrongly from there on.
                for kept in KEPT["aarch64" if "aarch64" in machine else "x86-64"]:
                    try:
                        unwound.add_saved_register(kept, pending.read_register(kept))
                    except (gdb.error, ValueError):
                        pass
                scanned.add(sp + at + 8)
                return unwound
        return None


def frames(thread):
    out, frame, level = [], None, 0
    try:
        frame = gdb.newest_frame()
    except gdb.error:
        return out, False
    while frame is not None and level < MAX_FRAMES:
        entry = {"level": level, "pc": "", "function": "", "file": "", "line": 0, "module": ""}
        try:
            pc = frame.pc()
            entry["pc"] = "0x%016x" % pc
            if level > 0 and int(frame.read_register("sp")) in scanned:
                entry["scanned"] = True
            entry["function"] = frame.name() or ""
            entry["module"] = inside(gdb.solib_name(pc) or exe)
            sal = frame.find_sal()
            if sal and sal.symtab:
                entry["file"], entry["line"] = sal.symtab.filename, sal.line
            entry.update(variables(frame))
            if level == 0:
                arch = frame.architecture()
                entry["registers"] = [{"name": r.name, "value": register(frame.read_register(r.name))} for r in arch.registers("general")]
            # The instructions from the frame's address on, from the program's file.
            entry["code"] = [{"address": "0x%016x" % i["addr"], "instruction": i["asm"]} for i in frame.architecture().disassemble(pc, count=8)]
        except (gdb.error, gdb.MemoryError, RuntimeError):
            pass
        out.append(entry)
        try:
            frame = frame.older()
        except gdb.error:
            break
        level += 1
    return out, frame is not None


gdb.unwinder.register_unwinder(None, ScanUnwinder(), replace=True)
gdb.execute("set pagination off")
gdb.execute("set confirm off")
# gdb asks debuginfod servers for the symbols of stripped files only where
# the operator named servers: the request tells them which programs run here.
gdb.execute("set debuginfod enabled " + ("on" if os.environ.get("DEBUGINFOD_URLS") else "off"))
if ROOT:
    gdb.execute("set sysroot " + ROOT)
loaded = run("core-file " + CORE)


def mappings():
    out = []
    for line in run("info proc mappings").splitlines():
        m = re.match(r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s*(.*)$", line)
        if m:
            out.append({"start": m.group(1), "end": m.group(2), "size": m.group(3), "offset": m.group(4), "file": m.group(5).strip()})
    return out


def inside(path):
    """A path as the program saw it, without the root that gdb reads it from."""
    return path[len(ROOT):] if ROOT and path.startswith(ROOT + "/") else path


# The core names its program by a shortened name; the mapped file with that
# name is the program. With the program's file gdb knows its functions.
short = re.search(r"exe = '(.*)'", run("info proc exe"))
short = os.path.basename(short.group(1)) if short else ""
mapped = [m["file"] for m in mappings() if m["file"].startswith("/")]
exe = next((f for f in mapped if short and os.path.basename(f).startswith(short)), mapped[0] if mapped else "")
if exe and os.path.exists(ROOT + exe):
    run("file " + ROOT + exe)
    loaded = run("core-file " + CORE)
generated = re.search(r"Core was generated by `(.*)'", loaded)

report = {
    "executable": exe,
    # gdb escapes the command line's spaces and quotes with backslashes.
    "commandLine": re.sub(r"\\(.)", r"\1", generated.group(1)) if generated else "",
    # What gdb says on opening the core of a crash: "Program terminated with signal SIGSEGV, Segmentation fault."
    "stopped": " ".join(l.strip() for l in loaded.splitlines() if "terminated with signal" in l),
    "symbols": bool(exe and os.path.exists(ROOT + exe)),
    "threads": [],
    "modules": [],
    "mappings": mappings(),
}
inferior = gdb.selected_inferior()
selected = gdb.selected_thread()
for thread in sorted(inferior.threads(), key=lambda t: t.num):
    thread.switch()
    stack, cut = frames(thread)
    report["threads"].append({"id": thread.num, "systemId": thread.ptid[1], "name": thread.name or "", "current": selected is not None and thread.num == selected.num, "frames": stack, "cut": cut})
# For a core that gcore wrote from outside the process's PID namespace, gdb
# lists the process once more under its ID inside, without registers.
readable = [t for t in report["threads"] if any(f["pc"] for f in t["frames"])]
if readable:
    report["threads"] = readable
for line in run("info sharedlibrary").splitlines():
    m = re.match(r"(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)\s+(?:\(\*\)\s+)?(\S.*)$", line)
    if m:
        report["modules"].append({"from": m.group(1), "to": m.group(2), "symbols": m.group(3) == "Yes", "file": inside(m.group(4))})

with open(OUT, "w") as f:
    json.dump(report, f)
