// The core viewer follows a debugger's view of a stopped program, as in
// Visual Studio Code: threads and the call stack on the left; the selected
// frame's variables, registers and instructions on the right; the modules
// and the memory map beside them. gdb described the core on the node, where
// the program's files were at hand; this page shows that description.
import {$, esc, address, file, loadText, notice, show} from './common.js';

const markup = `
  <div id="stopped"></div>
  <div id="debugger">
    <div id="side">
      <h4>Threads <input id="find" type="search" placeholder="Search" autocomplete="off" spellcheck="false"></h4>
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

export default async function (root) {
  let report;
  try { report = JSON.parse((await loadText(file.endsWith(suffix) ? address : address + suffix)).text); }
  catch (err) {
    if (err.status === 404) return notice('This core has no description: gdb could not read it on the node, or it was recorded before Asservat described cores. Download it and open it with gdb and the program\'s files.');
    throw err;
  }
  root.innerHTML = markup;
  const threads = report.threads || [];
  let thread = threads.find(t => t.current) || threads[0], frame = thread?.frames[0];

  $('stopped').innerHTML = `<span class="${report.stopped ? 'crash' : 'snap'}">${esc(report.stopped || 'Snapshot of a running process; it continued afterwards.')}</span>
    <code>${esc(report.commandLine || report.executable || '')}</code>
    ${report.symbols ? '' : '<span class="warn">The program\'s files were not at hand when the core was described: frames show addresses, not functions.</span>'}`;

  const table = (head, rows) => `<table><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
  const variables = (title, list) => !list?.length ? '' : `<h5>${title}</h5>` + table(['Name', 'Value', 'Type'], list.map(v => `<tr><td class="name">${esc(v.name)}</td><td class="value">${esc(v.value)}</td><td class="type">${esc(v.type)}</td></tr>`));
  const draw = () => {
    const words = $('find').value.toLowerCase();
    $('threads').innerHTML = threads.filter(t => !words || `${t.name} ${t.frames.map(named).join(' ')}`.toLowerCase().includes(words)).map(t =>
      `<div class="row${t === thread ? ' selected' : ''}" data-thread="${t.id}"><span>${t.current ? '<b title="The thread that gdb selected: for a crash, the one that crashed">●</b> ' : ''}Thread ${t.id}${t.name ? ` "${esc(t.name)}"` : ''} <span class="dim">LWP ${t.systemId}</span></span><span class="dim">${esc(t.frames[0] ? named(t.frames[0]) : '')}</span></div>`).join('') || '<div class="dim pad">No thread matches.</div>';
    $('stack').innerHTML = !thread ? '' : thread.frames.map(f => `<div class="row${f === frame ? ' selected' : ''}" data-level="${f.level}"><span>${esc(named(f))}</span><span class="dim">${esc(where(f))}</span></div>`).join('')
      + (thread.cut ? '<div class="dim pad">The stack goes deeper; the innermost 256 frames are shown.</div>' : '');
    $('frame').innerHTML = !frame ? '<p class="dim pad">This thread has no frames.</p>' : `
      <h3>#${frame.level} ${esc(named(frame))}</h3>
      <div class="dim">${frame.file ? `${esc(frame.file)}:${frame.line} · ` : ''}${esc(frame.module || '')} · ${esc(frame.pc)}</div>
      ${variables('Arguments', frame.arguments)}${variables('Locals', frame.locals)}
      ${frame.arguments?.length || frame.locals?.length ? '' : '<p class="dim">No variables: the program carries no debug information for this frame.</p>'}
      ${frame.code?.length ? '<h5>Instructions</h5><pre class="code">' + frame.code.map((i, n) => `<span class="${n ? '' : 'pc'}">${n ? '  ' : '=&gt;'} ${esc(i.address)}  ${esc(i.instruction)}</span>`).join('\n') + '</pre>' : ''}
      ${frame.registers?.length ? '<h5>Registers</h5><div class="registers">' + frame.registers.map(r => `<div><span class="name">${esc(r.name)}</span><span class="value">${esc(r.value)}</span></div>`).join('') + '</div>'
        : '<p class="dim">Registers are shown for the innermost frame.</p>'}`;
  };
  $('modules').innerHTML = table(['File', 'From', 'To', 'Symbols'], [`<tr><td class="name">${esc(report.executable || '')}</td><td></td><td></td><td>${report.symbols ? 'read' : 'not at hand'}</td></tr>`,
    ...(report.modules || []).map(m => `<tr><td class="name">${esc(m.file)}</td><td class="value">${esc(m.from)}</td><td class="value">${esc(m.to)}</td><td>${m.symbols ? 'read' : 'not at hand'}</td></tr>`)]);
  $('map').innerHTML = table(['Start', 'End', 'Size', 'Offset', 'File'], (report.mappings || []).map(m => `<tr><td class="value">${esc(m.start)}</td><td class="value">${esc(m.end)}</td><td class="value">${esc(m.size)}</td><td class="value">${esc(m.offset)}</td><td class="name">${esc(m.file)}</td></tr>`));

  $('find').oninput = draw;
  $('threads').onclick = e => { const r = e.target.closest('[data-thread]'); if (r) { thread = threads.find(t => t.id === Number(r.dataset.thread)); frame = thread.frames[0]; draw(); } };
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
