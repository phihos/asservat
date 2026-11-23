// The core viewer follows a debugger's view of a stopped program, as in
// Visual Studio Code: threads and the call stack on the left; the selected
// frame's variables, registers and instructions on the right; the modules
// and the memory map beside them. gdb described the core on the node, where
// the program's files were at hand; this page shows that description. For a
// Go program Delve added the goroutines, which the list then offers first.
import {$, esc, address, capture, file, headers, loadText, notice, show} from './common.js';

const markup = `
  <div id="stopped"></div>
  <div id="debugger">
    <div id="side">
      <h4><span id="kinds">Threads</span> <input id="find" type="search" placeholder="Search" autocomplete="off" spellcheck="false"></h4>
      <div id="threads" tabindex="0"></div>
      <h4>Call stack</h4>
      <div id="stack" tabindex="0"></div>
    </div>
    <div id="main">
      <div class="tabs"><button data-tab="frame" class="on">Frame</button><button data-tab="modules">Modules</button><button data-tab="map">Memory map</button></div>
      <div id="frame" class="tab"></div>
      <div id="modules" class="tab" hidden></div>
      <div id="map" class="tab" hidden></div>
    </div>
  </div>
`;
const suffix = '.analysis.json';
const base = path => path.split('/').pop();
const where = f => f.file ? `${base(f.file)}:${f.line}` : f.module ? base(f.module) : '';
const named = f => f.function || f.pc || '??';

// Dark in either theme, as a debugger is.
export const dark = true;
export default async function (root) {
  // A description from an older Asservat is made anew by the hub, from the
  // core and the program's files that the capture holds, before it shows.
  let kept = '';
  try {
    notice('Opening the core…');
    const res = await fetch(`/api/captures/${capture}/describe`, {method: 'POST', headers: {...headers, 'Content-Type': 'application/json'}, body: JSON.stringify({name: file.endsWith(suffix) ? file.slice(0, -suffix.length) : file})});
    if (res.ok) kept = (await res.json()).reason || '';
  } catch { /* the description as it is */ }
  show();
  let report;
  try { report = JSON.parse((await loadText(file.endsWith(suffix) ? address : address + suffix)).text); }
  catch (err) {
    if (err.status === 404) return notice('This core has no description: gdb could not read it on the node, or it was recorded before Asservat described cores. Download it and open it with gdb and the program\'s files.');
    throw err;
  }
  root.innerHTML = markup;
  // A goroutine has a call stack like a thread: both are listed, selected
  // and shown the same way. Registers and instructions exist for threads.
  const lists = {goroutines: report.goroutines || [], threads: report.threads || []};
  let kind = lists.goroutines.length ? 'goroutines' : 'threads', thread, frame;
  const choose = to => { kind = to; thread = lists[kind].find(t => t.current) || lists[kind][0]; frame = thread?.frames[0]; };
  choose(kind);
  if (lists.goroutines.length) $('kinds').innerHTML = '<button data-kind="goroutines">Goroutines</button><button data-kind="threads">Threads</button>';

  $('stopped').innerHTML = `<span class="${report.stopped ? 'crash' : 'snap'}">${esc(report.stopped || 'Snapshot of a running process; it continued afterwards.')}</span>
    <code>${esc(report.commandLine || report.executable || '')}</code>
    ${report.runtime ? `<span class="dim">${esc(report.runtime)}</span>` : ''}
    ${kept && !(report.describer > 1) ? `<span class="warn" title="${esc(kept)}">described by an older Asservat, which may show less; a new dump is described in full</span>` : ''}
    ${report.withoutDebugInfo ? '<span class="dim" title="The program was built without debug information. Functions, files and lines are from the line table that every Go program carries; variables cannot be shown.">no debug information: functions and lines, no variables</span>' : ''}
    ${report.symbols ? '' : '<span class="warn">The program\'s files were not at hand when the core was described: frames show addresses, not functions.</span>'}`;

  const table = (head, rows) => `<table><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
  const variables = (title, list) => !list?.length ? '' : `<h5>${title}</h5>` + table(['Name', 'Value', 'Type'], list.map(v => `<tr><td class="name">${esc(v.name)}</td>${value(v.value)}<td class="type">${esc(v.type)}</td></tr>`));
  // What the debugger says in place of a value it cannot read: a variable
  // that the compiler kept in no place at this instruction is "optimised out".
  const value = v => /^<.*>$/.test(v || '') ? `<td class="value dim" title="${esc(v)}">${/loclist|optimized|OP stack/.test(v) ? 'optimised out' : esc(v.slice(1, -1))}</td>` : `<td class="value">${esc(v)}</td>`;
  const rows = {
    threads: t => `<span>${t.current ? '<b title="The thread that gdb selected: for a crash, the one that crashed">●</b> ' : ''}Thread ${t.id}${t.name ? ` "${esc(t.name)}"` : ''} <span class="dim">LWP ${t.systemId}</span></span><span class="dim">${esc(t.frames[0] ? named(t.frames[0]) : '')}</span>`,
    goroutines: g => `<span>${g.current ? '<b title="The goroutine of the thread that the core selects: for a crash, the one that crashed">●</b> ' : ''}Goroutine ${g.id} <span class="dim">${esc(g.status)}${g.threadSystemId ? ` · LWP ${g.threadSystemId}` : ''}</span></span><span class="dim">${esc(g.function || (g.frames[0] ? named(g.frames[0]) : ''))}</span>`,
  };
  const draw = () => {
    const words = $('find').value.toLowerCase();
    for (const b of $('kinds').querySelectorAll('button')) b.classList.toggle('on', b.dataset.kind === kind);
    $('threads').innerHTML = (lists[kind].filter(t => !words || `${t.name || ''} ${t.status || ''} ${t.frames.map(named).join(' ')}`.toLowerCase().includes(words)).map(t =>
      `<div class="row${t === thread ? ' selected' : ''}" data-thread="${t.id}">${rows[kind](t)}</div>`).join('') || `<div class="dim pad">No ${kind === 'threads' ? 'thread' : 'goroutine'} matches.</div>`)
      + (kind === 'goroutines' && report.goroutinesCut ? `<div class="dim pad">The program has more goroutines; ${lists.goroutines.length} are shown, with those that run on a thread.</div>` : '');
    $('stack').innerHTML = !thread ? '' : thread.frames.map(f => `<div class="row${f === frame ? ' selected' : ''}" data-level="${f.level}"><span>${f.scanned ? '<span class="dim" title="Found by reading the stack">≈ </span>' : ''}${esc(named(f))}</span><span class="dim">${esc(where(f))}</span></div>`).join('')
      + (thread.frames.some(f => f.scanned) ? '<div class="dim pad">≈ A library on this stack carries no unwind tables (musl, the C library of Alpine images, is one). The frames above it were found by the return addresses on the stack: most likely right, not certain.</div>' : '')
      + (thread.cut ? '<div class="dim pad">The stack goes deeper; the innermost 256 frames are shown.</div>' : '');
    $('frame').innerHTML = !frame ? '<p class="dim pad">No frames.</p>' : `
      <h3>#${frame.level} ${esc(named(frame))}</h3>
      <div class="dim">${[frame.file && `${frame.file}:${frame.line}`, frame.module, frame.pc].filter(Boolean).map(esc).join(' · ')}</div>
      ${variables('Arguments', frame.arguments)}${variables('Locals', frame.locals)}
      ${frame.arguments?.length || frame.locals?.length ? '' : '<p class="dim">No variables: the program carries no debug information for this frame.</p>'}
      ${frame.code?.length ? '<h5>Instructions</h5><pre class="code">' + frame.code.map((i, n) => `<span class="${n ? '' : 'pc'}">${n ? '  ' : '=&gt;'} ${esc(i.address)}  ${esc(i.instruction)}</span>`).join('\n') + '</pre>' : ''}
      ${frame.registers?.length ? '<h5>Registers</h5><div class="registers">' + frame.registers.map(r => `<div><span class="name">${esc(r.name)}</span><span class="value">${esc(r.value)}</span></div>`).join('') + '</div>'
        : `<p class="dim">${kind === 'threads' ? 'Registers are shown for the innermost frame.' : 'Registers and instructions are shown for threads.'}</p>`}`;
  };
  $('modules').innerHTML = table(['File', 'From', 'To', 'Symbols'], [`<tr><td class="name">${esc(report.executable || '')}</td><td></td><td></td><td>${report.symbols ? 'read' : 'not at hand'}</td></tr>`,
    ...(report.modules || []).map(m => `<tr><td class="name">${esc(m.file)}</td><td class="value">${esc(m.from)}</td><td class="value">${esc(m.to)}</td><td>${m.symbols ? 'read' : 'not at hand'}</td></tr>`)]);
  $('map').innerHTML = table(['Start', 'End', 'Size', 'Offset', 'File'], (report.mappings || []).map(m => `<tr><td class="value">${esc(m.start)}</td><td class="value">${esc(m.end)}</td><td class="value">${esc(m.size)}</td><td class="value">${esc(m.offset)}</td><td class="name">${esc(m.file)}</td></tr>`));

  $('find').oninput = draw;
  $('kinds').onclick = e => { if (e.target.dataset.kind) { choose(e.target.dataset.kind); draw(); } };
  $('threads').onclick = e => { const r = e.target.closest('[data-thread]'); if (r) { thread = lists[kind].find(t => t.id === Number(r.dataset.thread)); frame = thread.frames[0]; draw(); } };
  $('stack').onclick = e => { const r = e.target.closest('[data-level]'); if (r) { frame = thread.frames[Number(r.dataset.level)]; draw(); } };
  $('stack').onkeydown = e => {
    const step = {ArrowDown: 1, ArrowUp: -1}[e.key], to = thread?.frames[(frame?.level ?? 0) + step];
    if (!step || !to) return;
    e.preventDefault();
    frame = to; draw();
    $('stack').querySelector('.selected')?.scrollIntoView({block: 'nearest'});
  };
  root.querySelector('.tabs').onclick = e => {
    const name = e.target.dataset.tab;
    if (!name) return;
    for (const b of root.querySelectorAll('[data-tab]')) b.classList.toggle('on', b === e.target);
    for (const id of ['frame', 'modules', 'map']) $(id).hidden = id !== name;
  };
  show();
  draw();
}
