# Reads the Python stacks of a core with pystack and writes them as JSON:
# for each thread of the interpreter its frames, innermost first, with
# their arguments and local variables. Run by the Python that has pystack.
#
#   python_stacks.py <core> <executable> <library search path> <most frames> <longest value>
import json
import sys

from pystack.engine import NativeReportingMode, StackMethod, get_process_threads_for_core

core, executable, libraries, most, longest = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
threads, version = [], None
for thread in get_process_threads_for_core(core, executable, library_search_path=libraries, native_mode=NativeReportingMode.OFF, locals=True, method=StackMethod.AUTO):
    version = version or thread.python_version
    frames = []
    # pystack lists a thread's frames from its first call on.
    for frame in reversed(list(thread.frames)):
        variables = lambda found: [{"name": name, "type": "", "value": value if len(value) <= longest else value[:longest] + "…"} for name, value in found.items()]
        frames.append({"level": len(frames), "pc": "", "function": frame.code.scope, "file": frame.code.filename, "line": frame.code.location.lineno,
                       "arguments": variables(frame.arguments), "locals": variables(frame.locals)})
    # No name: a core holds none, and pystack would take that of whatever
    # process has the thread's number on the machine that reads the core.
    status = ", ".join(s for s in (thread.gil_status, thread.gc_status) if s)
    threads.append({"id": thread.tid, "name": "", "status": status, "current": False, "threadSystemId": thread.tid,
                    "frames": frames[:most], "cut": len(frames) > most})
json.dump({"runtime": "python", "title": "Python threads", "version": ".".join(str(n) for n in version) if version else "", "threads": threads}, sys.stdout)
