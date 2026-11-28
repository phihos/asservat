// Opens the console and every viewer in a headless browser, as wide as a
// desk and as narrow as a phone, and fails on what a person would see as
// broken: a script's error, a failed request, a file that does not open, a
// page that runs out of the screen sideways. It drives Chromium over its
// DevTools protocol with what Node has, and needs no package.
//
//   node test/e2e/browser.mjs <hub URL> <token> [an administrator's token]
//
// With an administrator's token it also looks at what only administrators
// see: the audit log, and the list of everyone's captures.
//
// $WATCHES is how many watches wait at least: the page of watches then has to
// list them.
// $UNREADABLE names files, separated by commas, that are known not to be
// what their names say: of those the viewer must say that the hub could not
// open them. With $ONLY_NAMESPACES, a regular expression, it opens only the files of
// captures from namespaces that match: for a hub that holds more than tests.
//
// With $SHOTS, a directory, it saves a picture of every page it checked.
//
// The browser is $CHROME, or the first of the usual names that is installed.
import {spawn, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const [hub, token, adminToken] = process.argv.slice(2);
const chrome = process.env.CHROME || ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'].find(name => spawnSync('sh', ['-c', `command -v ${name}`]).status === 0);
if (!hub || !token) { console.error('usage: browser.mjs <hub URL> <token>'); process.exit(2); }
// 78 says that there is no browser, and nothing else does.
if (!chrome) { console.error('no Chromium or Chrome is installed'); process.exit(78); }

const env = {...process.env}; delete env.LD_LIBRARY_PATH;
// The browser's helpers write into the profile for a moment after the browser has ended.
const removed = dir => { try { rmSync(dir, {recursive: true, force: true, maxRetries: 25, retryDelay: 200}); } catch {} };
// Chromium says on its standard error where its DevTools listen. On a busy
// machine it was seen once to say nothing of the kind for half a minute,
// for a reason its output did not tell: a browser that does not start is
// ended and started again, twice at most, before the check gives up. Each
// start has a profile of its own, since a browser that is killed leaves its
// lock in the one it had.
const start = () => new Promise((found, failed) => {
  const profile = mkdtempSync(join(tmpdir(), 'asservat-browser-'));
  const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], {env, stdio: ['ignore', 'ignore', 'pipe']});
  let said = '', gone = false;
  // The next start waits until this browser has ended and its profile is removed.
  const giveUp = why => {
    clearTimeout(late);
    const over = () => { removed(profile); failed(new Error(why + ': ' + said.slice(-400))); };
    if (gone) return over();
    browser.once('exit', over);
    browser.kill('SIGKILL');
  };
  const late = setTimeout(() => giveUp('the browser did not start'), 30000);
  const ended = code => { gone = true; giveUp(`the browser ended with ${code}`); };
  browser.on('exit', ended);
  browser.stderr.on('data', d => {
    said += d;
    const m = /DevTools listening on ws:\/\/([^/]+)\//.exec(said);
    if (m) { clearTimeout(late); browser.off('exit', ended); found([browser, m[1], profile]); }
  });
});
let started;
for (let tries = 3; !started; tries--) {
  started = await start().catch(e => { if (tries === 1) throw e; console.error(e.message.split('\n')[0] + '; starting it again'); });
}
const [browser, listening, profile] = started;
const sleep = ms => new Promise(r => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) { target = (await (await fetch(`http://${listening}/json`).catch(() => null))?.json().catch(() => []) || []).find(t => t.type === 'page'); if (!target) await sleep(100); }
if (!target) { console.error('the browser shows no page'); browser.kill(); process.exit(1); }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let id = 0, seen = [], signedOut = false, hostile = [];
const waiting = new Map();
ws.onmessage = m => {
  const d = JSON.parse(m.data);
  if (d.id) { waiting.get(d.id)?.(d); waiting.delete(d.id); }
  else if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') seen.push('console: ' + d.params.args.map(a => a.value ?? a.description).join(' '));
  // A request that is held up while hostile answers are on: answered with the hostile one for its address, or let go.
  else if (d.method === 'Fetch.requestPaused') {
    const answer = hostile.find(([at]) => at.test(new URL(d.params.request.url).pathname + new URL(d.params.request.url).search));
    if (answer) send('Fetch.fulfillRequest', {requestId: d.params.requestId, responseCode: 200, responseHeaders: [{name: 'Content-Type', value: 'application/json'}], body: Buffer.from(JSON.stringify(answer[1])).toString('base64')});
    else send('Fetch.continueRequest', {requestId: d.params.requestId});
  }
  // Before signing in the console asks who is there and is told nobody. What a
  // page had begun to ask when the check signed it out is refused as well,
  // and says so.
  else if (d.method === 'Runtime.exceptionThrown') { const said = d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text; if (!(signedOut && /sign in with a bearer token/.test(said))) seen.push('exception: ' + said); }
  else if (d.method === 'Network.responseReceived' && d.params.response.status >= 400 && !(signedOut && d.params.response.status === 401)) seen.push(`HTTP ${d.params.response.status} ${d.params.response.url}`);
};
// A browser that ends, or hangs up, answers nothing more: what waits for it fails.
ws.onclose = () => { for (const answer of waiting.values()) answer({result: {exceptionDetails: {text: 'the browser hung up'}}}); waiting.clear(); };
const send = (method, params = {}) => ws.readyState !== WebSocket.OPEN ? Promise.resolve({result: {exceptionDetails: {text: 'the browser hung up'}}}) : new Promise(r => { waiting.set(++id, r); ws.send(JSON.stringify({id, method, params})); });
const run = async expression => {
  const r = await send('Runtime.evaluate', {expression: `(async () => { ${expression} })()`, awaitPromise: true, returnByValue: true});
  if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'the page could not be asked');
  return r.result.result.value;
};
// until asks the page again and again, for as long as a slow runner may take.
const until = async (what, expression, seconds = 30) => {
  for (let i = 0; i < seconds * 5; i++) { if (await run(expression).catch(() => false)) return; await sleep(200); }
  throw new Error('waited in vain for ' + what);
};
for (const domain of ['Runtime', 'Page', 'Network']) await send(domain + '.enable');

const widths = {desk: [1400, 900, false], phone: [390, 844, true]};
const failures = [];
// A check has a name; what the browser complains of meanwhile is its failure.
const check = async (name, steps) => {
  seen = [];
  try { await steps(); } catch (err) { seen.push(err.message); }
  // A page may be as wide as it likes inside its own scrolling parts, not as a whole.
  const wide = await run(`return document.documentElement.scrollWidth > innerWidth + 1 ? document.documentElement.scrollWidth + ' of ' + innerWidth : ''`).catch(() => '');
  if (wide) seen.push('the page is wider than the screen: ' + wide + ' px');
  if (process.env.SHOTS) {
    // The page as it stood when it was checked, for a person to look at.
    const shot = await send('Page.captureScreenshot', {format: 'png'});
    mkdirSync(process.env.SHOTS, {recursive: true});
    if (shot.result?.data) writeFileSync(join(process.env.SHOTS, name.replace(/[^a-z0-9.]+/gi, '-') + '.png'), Buffer.from(shot.result.data, 'base64'));
  }
  for (const problem of new Set(seen)) failures.push(`${name}: ${problem}`);
  console.log(`${seen.length ? 'FAIL' : 'ok  '} ${name}`);
};
const open = async url => { await send('Page.navigate', {url}); await until('the page', `return document.readyState === 'complete'`); };

// choose picks a workload in the form for a new capture, as its user does:
// the first cluster, a namespace that these checks may use, and the first workload in it. It
// says whether there was one.
const choose = async () => {
  // Of several clusters none is chosen for the user either.
  await until('clusters to choose from', `return [...document.getElementById('cluster').options].some(o => o.value)`);
  await run(`const c = document.getElementById('cluster'); if (!c.value) { c.value = [...c.options].find(o => o.value).value; c.dispatchEvent(new Event('change', {bubbles: true})); }`);
  await until('namespaces to choose from', `return [...document.getElementById('namespace').options].some(o => o.value)`);
  const namespace = (await run(`return [...document.getElementById('namespace').options].map(o => o.value)`)).find(n => n && new RegExp(process.env.ONLY_NAMESPACES || '').test(n));
  if (!namespace) return false;
  await run(`const n = document.getElementById('namespace'); if (n.value !== ${JSON.stringify(namespace)}) { n.value = ${JSON.stringify(namespace)}; n.dispatchEvent(new Event('change', {bubbles: true})); }`);
  await until('workloads to choose from', `return [...document.getElementById('workload').options].some(o => o.value)`);
  await run(`const w = document.getElementById('workload'); if (!w.value) { w.value = [...w.options].find(o => o.value).value; w.dispatchEvent(new Event('change', {bubbles: true})); }`);
  return true;
};
for (const [size, [width, height, mobile]] of Object.entries(widths)) {
  await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
  await check(`${size}: signing in`, async () => {
    signedOut = true;
    await open(hub + '/');
    // As someone who has not signed in, also the second time round.
    await run(`sessionStorage.clear(); document.cookie = 'asservat_token=; path=/; max-age=0'; location.reload()`);
    await until('the sign-in form', `return !document.getElementById('login').hidden`);
    const off = await run(`const box = document.getElementById('login').getBoundingClientRect(); return Math.round(Math.abs(box.left + box.width / 2 - document.documentElement.clientWidth / 2))`);
    if (off > 2) throw new Error(`the sign-in form stands ${off} px off the middle of the page`);
    signedOut = false;
    await run(`sessionStorage.setItem('token', ${JSON.stringify(token)}); location.reload()`);
    await until('the list of captures', `return !document.getElementById('app').hidden && document.querySelector('.capture, #noCaptures:not([hidden])')`);
  });
  for (const view of ['captures', 'watches', 'clusters']) await check(`${size}: ${view}`, async () => {
    await run(`location.hash = '#${view}'`);
    await until('the page ' + view, `return !document.querySelector('[data-view=${view}]').hidden`);
    // Where the run says how many watches wait, the page lists them, each with its buttons on one line.
    if (view === 'watches' && process.env.WATCHES) {
      await until('the watches', `return document.querySelectorAll('#watches tr').length >= ${Number(process.env.WATCHES)}`);
      const stacked = await run(`return [...document.querySelectorAll('#watches tr')].some(row => { const tops = [...row.querySelectorAll('button')].map(b => Math.round(b.getBoundingClientRect().top)); return new Set(tops).size > 1; })`);
      if (stacked) throw new Error('the buttons of a watch stand above one another');
    }
    if (view === 'captures') {
      // A capture's details and files open with the keyboard alone.
      await run(`document.querySelector('.capture:not(.open) .chev')?.focus()`);
      for (const type of ['keyDown', 'keyUp']) await send('Input.dispatchKeyEvent', {type, key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: type === 'keyDown' ? '\r' : undefined});
      await sleep(300);
      const opened = await run(`return (() => { const b = document.activeElement; return !b.classList.contains('chev') || (b.closest('.capture').classList.contains('open') && b.getAttribute('aria-expanded') === 'true'); })()`);
      if (!opened) throw new Error('Enter on a capture did not open its details');
      // The list is written anew with every change: the focus stays on the link it was on.
      const kept = await run(`const link = document.querySelector('.capture.open a.open, .capture.open a[href*="/artifacts/"]'); if (!link) return true; link.focus(); const href = link.getAttribute('href'); await loadCaptures(); return document.activeElement.getAttribute('href') === href`);
      if (!kept) throw new Error('the focus left a file\'s link when the list was written anew');
    }
  });
  await check(`${size}: a new capture, step by step`, async () => {
    await run(`location.hash = '#new'`);
    if (!await choose()) return;
    const next = `[...document.querySelectorAll('[data-view=new] button')].find(b => b.offsetParent && /Next/.test(b.innerText))?.click()`;
    await run(next); await sleep(300);
    // Every recording but the profile endpoint, which needs an endpoint chosen.
    await run(`for (const box of document.querySelectorAll('input[name=kind]')) if (!box.checked && box.value !== 'pprof') box.click()`);
    await run(next); await sleep(1500);
    await run(next); await sleep(300);
    await until('the last step', `return !!document.querySelector('input[name=when]')?.offsetParent`);
    // The fields of an endpoint of one's own stand in a line: their names at one height. They are shown for the look only.
    const apart = await run(`const step = document.querySelector('fieldset[data-step="3"]'), part = document.getElementById('profileSection'), other = document.getElementById('otherEndpoint'), was = [step.hidden, part.hidden, other.open];
      step.hidden = part.hidden = false; other.open = true;
      const top = id => document.getElementById(id).closest('label').firstChild, at = id => { const r = document.createRange(); r.selectNodeContents(top(id)); return r.getBoundingClientRect().top; };
      const apart = Math.abs(at('profilePort') - at('profilePath'));
      [step.hidden, part.hidden, other.open] = was; return apart`);
    if (size === 'desk' && apart > 1) throw new Error(`"Port" and "Path" of a custom endpoint stand ${apart} px apart in height`);
    // Every way to start shows its own fields.
    const ways = await run(`return [...document.querySelectorAll('input[name=when]')].map(i => i.value)`);
    for (const way of ways) { await run(`document.querySelector('input[name=when][value="${way}"]').click()`); await sleep(50); }
  });
  // The form chooses nothing for its user where there is a choice, says in
  // its line of choices what is chosen from the start, and shows what a
  // condition asks for at the condition, in sight, and not below all of them.
  await check(`${size}: the form chooses nothing by itself and asks at the condition`, async () => {
    // Loaded anew: what an earlier check chose is gone.
    await run(`location.hash = '#new'; location.reload()`); await sleep(1500);
    await until('namespaces to choose from', `return document.getElementById('namespace')?.options.length > 0 && !document.getElementById('app').hidden`);
    await sleep(800);
    const begun = JSON.parse(await run(`const n = document.getElementById('namespace'), w = document.getElementById('workload');
      const none = document.querySelector('#steps li.skip .none'), text = document.createRange(); if (none) text.selectNodeContents(none.previousSibling);
      return JSON.stringify({namespaces: [...n.options].map(o => o.value), namespace: n.value, workload: w.value, summary: document.getElementById('summary').innerText,
        gap: none ? none.getBoundingClientRect().left - text.getBoundingClientRect().right : 0})`));
    if (begun.namespaces.filter(Boolean).length > 1 && (begun.namespace || begun.workload)) throw new Error(`with ${begun.namespaces.length} namespaces to choose from, the form began with ${begun.namespace} and ${begun.workload}`);
    if (begun.workload && !begun.summary.includes(begun.workload)) throw new Error(`the form began with ${begun.workload} chosen and its line of choices says "${begun.summary}"`);
    if (begun.gap > 2) throw new Error(`"none needed" stands ${begun.gap} px away from the step it belongs to`);
    // The rest is done where this check may: in a namespace of its own.
    if (!await choose()) return;
    await until('the workload in the line of choices', `return document.getElementById('summary').innerText.includes(document.getElementById('workload').value)`, 10);
    const next = `document.getElementById('next').offsetParent && document.getElementById('next').click()`;
    await run(next); await sleep(300);
    await run(`for (const box of document.querySelectorAll('input[name=kind]')) if (box.checked !== ['pod-state', 'cpu'].includes(box.value)) box.click()`);
    await run(next); await sleep(600); await run(next); await sleep(500);
    await until('the last step', `return !!document.querySelector('input[name=when]')?.offsetParent`);
    await run(`document.querySelector('input[name=when][value=log]').click()`);
    await until('what the chosen condition asks for, in sight', `const fields = document.getElementById('logFields').getBoundingClientRect(); return fields.bottom <= innerHeight + 1 && fields.top >= 0`, 5).catch(() => {});
    await sleep(300);
    // Wide, the conditions stand in rows and it is below them; narrow, right below the chosen one.
    const asked = JSON.parse(await run(`const fields = document.getElementById('logFields').getBoundingClientRect(), group = document.querySelector('input[name=when]:checked').closest(${JSON.stringify(size === 'phone' ? 'label' : '.choice')}).getBoundingClientRect();
      const name = document.createRange(); name.selectNodeContents([...document.querySelector('[data-before=cpu]').childNodes].find(n => n.nodeType === 3 && n.textContent.trim()));
      return JSON.stringify({below: fields.top - group.bottom, seen: fields.bottom <= innerHeight + 1 && fields.top >= 0, lines: name.getClientRects().length,
        pattern: document.getElementById('logPattern').getBoundingClientRect().right, container: document.getElementById('logContainer').getBoundingClientRect().right})`));
    if (asked.below < 0 || asked.below > 40) throw new Error(`what the condition asks for stands ${asked.below} px below its group`);
    if (!asked.seen) throw new Error('what the chosen condition asks for is out of sight');
    // Where the fields stand is decided while the step is shown: they are there also after it was left with another kind of recording chosen.
    await run(`document.querySelector('input[name=when][value=cpu]').click()`); await sleep(200);
    await run(`document.getElementById('back').click()`); await sleep(300); await run(next); await sleep(400);
    const again = await run(`return document.getElementById('usageFields').getBoundingClientRect().top - document.querySelector('input[name=when]:checked').closest(${JSON.stringify(size === 'phone' ? 'label' : '.choice')}).getBoundingClientRect().bottom`);
    if (again < 0 || again > 40) throw new Error(`after the step was left and come back to, what the condition asks for stands ${again} px below it`);
    await run(`document.querySelector('input[name=when][value=log]').click()`); await sleep(400);
    if (asked.lines > 1) throw new Error(`the name of a recording to keep running is broken into ${asked.lines} lines`);
    if (size === 'phone' && Math.abs(asked.pattern - asked.container) > 1) throw new Error(`the fields of the condition end at ${asked.pattern} and ${asked.container} px`);
    // What is missing is said, and the cursor stands where it is to be entered.
    await run(`document.getElementById('submit').click()`); await sleep(500);
    const missing = JSON.parse(await run(`return JSON.stringify({said: document.getElementById('formProblem').innerText, at: document.activeElement.id})`));
    if (!/pattern/.test(missing.said) || missing.at !== 'logPattern') throw new Error(`without a pattern the form says "${missing.said}" and the cursor is in "${missing.at}"`);
  });
  // One file per viewer and kind of file, of the captures that this user sees.
  const files = await run(`const list = await (await fetch('/api/captures', {headers: {Authorization: 'Bearer ' + sessionStorage.getItem('token')}})).json();
    const seen = new Set(), files = [];
    for (const c of list) if (new RegExp(${JSON.stringify(process.env.ONLY_NAMESPACES || '')}).test(c.namespace)) for (const a of c.artifacts) {
      const kind = a.viewer + ' ' + a.name.split('/').pop().replace(/^.*?([a-z]+\\.?[a-z]*)$/, '$1');
      if (a.viewer && a.size && !seen.has(kind)) { seen.add(kind); files.push({capture: c.id, name: a.name, viewer: a.viewer}); }
    }
    return files`);
  if (!files.length) failures.push(`${size}: no file with a viewer to open`);
  for (const file of files) await check(`${size}: ${file.viewer} viewer, ${file.name.split('/').pop()}`, async () => {
    await open(`${hub}/view?capture=${file.capture}&file=${encodeURIComponent(file.name)}`);
    // The file is open when the viewer shows and the notice has gone; a notice that stays says why not.
    await until('the file to open', `const n = document.getElementById('notice'); return !document.getElementById('root').hidden || (!n.hidden && !/^Opening/.test(n.textContent.trim()))`, 120);
    const notice = await run(`const n = document.getElementById('notice'); return document.getElementById('root').hidden ? n.textContent.trim() : ''`);
    if ((process.env.UNREADABLE || '').split(',').includes(file.name.split('/').pop())) {
      // The hub refused the file, which is the request that failed.
      seen = seen.filter(problem => !problem.startsWith('HTTP 422 '));
      if (!notice.startsWith('The hub could not open this file')) throw new Error('a file that is not what its name says opened, or the viewer did not say why not: ' + notice);
      return;
    }
    if (notice) throw new Error('the file did not open: ' + notice);
    // Every view of the file, and the first row of its list.
    const tabs = await run(`return [...document.querySelectorAll('#root [data-tab]')].filter(b => !b.hidden).map(b => b.dataset.tab)`);
    for (const tab of tabs) {
      await run(`document.querySelector('#root [data-tab="${tab}"]').click()`); await sleep(150);
      // A summary says which call its numbers are of without scrolling sideways.
      const hidden = await run(`const name = document.querySelector('#summary:not([hidden]) tbody td.name'); if (!name) return false; const at = name.getBoundingClientRect(); return at.left < 0 || at.right > innerWidth`);
      if (hidden) throw new Error('the summary\'s numbers stand without the name of their call in sight');
      // A stack's frame begins on the line of its "at", however long it is.
      const alone = await run(`return [...document.querySelectorAll('#threads:not([hidden]) .frames div')].some(frame => { const text = frame.firstChild; if (!text || text.nodeType !== 3 || text.length < 5) return false; const start = document.createRange(); start.setStart(text, 0); start.setEnd(text, 5); return start.getClientRects().length > 1; })`);
      if (alone) throw new Error('a frame of a stack stands on the line below its "at"');
      // An address in a core's modules and mappings stands on one line.
      const broken = await run(`return [...document.querySelectorAll('#modules:not([hidden]) td.value, #map:not([hidden]) td.value')].some(cell => { const range = document.createRange(); range.selectNodeContents(cell); return range.getClientRects().length > 1; })`);
      if (broken) throw new Error('an address of a core is broken over several lines');
    }
    await run(`document.querySelector('#root .row, #root .c, #root .l, #root .g')?.click()`); await sleep(150);
    // A thread without frames says so where its stack would stand.
    const silent = await run(`const kinds = [...document.querySelectorAll('#kinds button')].map(b => b.dataset.kind); for (const kind of kinds.length ? kinds : ['']) { if (kind) document.querySelector('#kinds [data-kind="' + kind + '"]').click(); for (const id of [...document.querySelectorAll('#threads [data-thread]')].slice(0, 50).map(r => r.dataset.thread)) { document.querySelector('#threads [data-thread="' + id + '"]').click(); if (!document.getElementById('stack').textContent.trim()) return (kind || 'threads') + ' ' + id; } } document.querySelector('#kinds button')?.click(); return ''`);
    if (silent) throw new Error('the stack of a thread without frames is left empty: ' + silent);
    // A core's threads are gone through with the arrow keys.
    const second = await run(`const rows = document.querySelectorAll('#threads [data-thread]'); if (rows.length < 2) return ''; rows[0].click(); document.getElementById('threads').focus(); return rows[1].dataset.thread`);
    if (second) {
      for (const type of ['keyDown', 'keyUp']) await send('Input.dispatchKeyEvent', {type, key: 'ArrowDown', code: 'ArrowDown', windowsVirtualKeyCode: 40});
      await sleep(150);
      if (await run(`return document.querySelector('#threads .selected')?.dataset.thread`) !== second) throw new Error('the arrow key did not go to the next thread');
    }
  });
}
// A step of the new capture that has nothing to set for what is chosen, as
// "Details" has for the pod state that is chosen at first, says so. Struck
// through, as it was, it read as something broken.
await check('desk: a step with nothing to set says so', async () => {
  await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
  await open(hub + '/#new');
  await until('the steps', `return document.querySelector('#steps li.on')`);
  await run(`for (const box of document.querySelectorAll('input[name=kind]')) box.checked = box.value === 'pod-state'; document.querySelector('input[name=kind]').dispatchEvent(new Event('change', {bubbles: true}))`);
  await sleep(200);
  const details = await run(`const li = document.querySelector('#steps li[data-go="3"]'); return JSON.stringify({text: li.innerText.replace(/\s+/g, ' ').trim(), line: getComputedStyle(li).textDecorationLine, title: li.title, skipped: li.classList.contains('skip')})`);
  const {text, line, title, skipped} = JSON.parse(details);
  if (!skipped) throw new Error('the pod state has details to set: ' + details);
  if (line.includes('line-through')) throw new Error('the step is struck through');
  if (!/none needed/i.test(text) || !/nothing to set/i.test(title)) throw new Error('the step does not say why it is left out: ' + details);
  // With something to set it is a step like the others.
  await run(`for (const box of document.querySelectorAll('input[name=kind]')) box.checked = box.value === 'pcap'; document.querySelector('input[name=kind]').dispatchEvent(new Event('change', {bubbles: true}))`);
  await sleep(200);
  const with_ = JSON.parse(await run(`const li = document.querySelector('#steps li[data-go="3"]'); return JSON.stringify({text: li.innerText.replace(/\s+/g, ' ').trim(), title: li.title, skipped: li.classList.contains('skip')})`));
  if (with_.skipped || /none needed/i.test(with_.text) || with_.title) throw new Error('a step with something to set: ' + JSON.stringify(with_));
});
// Who opens a capture, goes to one of its files and comes back with the
// browser's own way back finds the list as it was left: the capture open,
// and the page where it stood.
for (const [size, [width, height, mobile]] of Object.entries(widths)) await check(`${size}: back from a file to the capture that was open`, async () => {
  await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
  await open(hub + '/#captures');
  await until('the list', `return document.querySelector('.capture')`);
  // The last capture with a file that opens in a viewer: far down, where there are several.
  const id = await run(`for (const c of document.querySelectorAll('.capture.open .chev')) c.click();
    const with_ = [...document.querySelectorAll('.capture')].filter(c => c.querySelector('a.open'));
    const card = with_.at(-1); if (!card) return '';
    card.querySelector('.chev').click(); card.querySelector('a.open').scrollIntoView({block: 'center'});
    return card.dataset.capture`);
  if (!id) throw new Error('no capture with a file to open');
  await sleep(200);
  const before = await run(`return JSON.stringify({open: [...document.querySelectorAll('.capture.open')].map(c => c.dataset.capture), at: Math.round(scrollY)})`);
  await run(`document.querySelector('.capture[data-capture="${id}"] a.open').click()`);
  await until('the viewer', `return location.pathname === '/view'`);
  await sleep(500);
  await run(`history.back()`);
  await until('the list again', `return location.pathname === '/' && document.querySelector('.capture')`);
  await sleep(700);
  const after = await run(`return JSON.stringify({open: [...document.querySelectorAll('.capture.open')].map(c => c.dataset.capture), at: Math.round(scrollY)})`);
  if (JSON.parse(after).open.join() !== JSON.parse(before).open.join()) throw new Error(`open before: ${before}, after coming back: ${after}`);
  if (Math.abs(JSON.parse(after).at - JSON.parse(before).at) > 40) throw new Error(`the page stood at ${JSON.parse(before).at} px and came back at ${JSON.parse(after).at} px`);
});

// What a cluster's agent or a workload can make the hub hand out is not
// trusted by the pages: values that carry script where numbers and states
// belong, and a link that names a recorded file as the capture, run none.
{
  const script = '<img src="data:image/png,x" onerror="window.scripted = 1">', made = '00000000-0000-4000-8000-00000000000a';
  const capture = {id: made, number: 9, cluster: 'c', namespace: 'n', workload: 'Deployment/w', requester: 'someone', state: 'Completed', createdAt: new Date().toISOString(), recordings: [{kind: 'logs'}],
    reason: script, message: script,
    tasks: [{pod: 'p', node: script, state: 'Completed', message: script, recordings: [{kind: 'logs', state: 'x"> ' + script, message: script}]}],
    artifacts: [{name: 'p/pod.json', size: 1, sha256: script, viewer: 'kube'}, {name: 'p/core.x', size: 1, sha256: 'a', viewer: 'core'}, {name: 'p/core.x.analysis.json', size: 1, sha256: 'a', viewer: 'core'}]};
  const pod = {metadata: {name: script, namespace: script, labels: {[script]: script}}, spec: {nodeName: script, containers: [{name: 'a', image: script, ports: [{containerPort: script, protocol: script}],
      livenessProbe: {tcpSocket: {port: script}, periodSeconds: script}}]},
    status: {phase: script, containerStatuses: [{name: 'a', restartCount: script, ready: true, state: {terminated: {exitCode: script, signal: script, reason: script}}}], conditions: [{type: script, status: script}]}};
  const frame = {level: script, function: script, file: script, line: script, pc: script, registers: [{name: script, value: script}], code: [{address: script, instruction: script}], arguments: [{name: script, value: script, type: script}]};
  const core = {describer: 99, executable: script, stopped: script, signal: script, threads: [{id: script, systemId: script, name: script, current: true, frames: [frame]}],
    goroutines: [{id: script, status: script, threadSystemId: script, function: script, frames: [frame]}], runtimeStacks: [{runtime: script, title: script, threads: [{id: script, threadSystemId: script, frames: [frame]}]}],
    modules: [{file: script, from: script, to: script}], mappings: [{start: script, end: script, size: script, offset: script, file: script}]};
  hostile = [[new RegExp(`^/api/captures/${made}$`), capture], [new RegExp(`^/api/captures/${made}/artifacts/p/pod\\.json$`), pod], [new RegExp(`^/api/captures/${made}/artifacts/p/core\\.x\\.analysis\\.json$`), core],
    [new RegExp(`^/api/captures/${made}/describe$`), {described: false}], [/^\/api\/captures(\?.*)?$/, [capture]]];
  await send('Fetch.enable', {patterns: [{urlPattern: '*/api/captures*'}, {urlPattern: '*/api/approvals*'}]});
  const scripted = () => run(`return window.scripted || document.querySelector('img[onerror]') ? 'script from hostile data reached the page' : ''`);
  for (const file of ['p/pod.json', 'p/core.x']) await check(`hostile data in the ${file.includes('pod') ? 'pod' : 'core'} viewer`, async () => {
    await open(`${hub}/view?capture=${made}&file=${encodeURIComponent(file)}`);
    await until('the viewer', `return !document.getElementById('root').hidden || !document.getElementById('notice').classList.contains('opening')`);
    await sleep(300);
    for (const tab of await run(`return [...document.querySelectorAll('#root [data-tab]')].filter(b => !b.hidden).map(b => b.dataset.tab)`)) { await run(`document.querySelector('#root [data-tab="${tab}"]').click()`); await sleep(100); }
    for (const kind of await run(`return [...document.querySelectorAll('#kinds button')].map((b, i) => i)`)) { await run(`document.querySelectorAll('#kinds button')[${kind}].click()`); await sleep(100); }
    const problem = await scripted();
    if (problem) throw new Error(problem);
  });
  await check('hostile data in the list of captures', async () => {
    await open(hub + '/#captures');
    await until('the list', `return document.querySelector('.capture')`);
    await run(`document.querySelector('.capture .chev').click()`); await sleep(200);
    const problem = await scripted();
    if (problem) throw new Error(problem);
  });
  await check('a link that names a file as the capture', async () => {
    await open(`${hub}/view?capture=${made}%2Fartifacts%2Fp%2Fpod.json%3F&file=p/pod.json`);
    await until('the refusal', `return !document.getElementById('notice').classList.contains('opening')`);
    if (!/No file was specified/.test(await run(`return document.getElementById('notice').innerText`))) throw new Error('the viewer took a path for a capture');
  });
  // A capture of a workload with many pods lists them a line each, and a
  // pod's files when it is opened: with all of them open, a capture of 200
  // pods was a page of 55,000 pixels.
  const kinds = ['logs', 'pod-state', 'pcap'], podsOf = n => Array.from({length: n}, (_, i) => `web-${String(i).padStart(3, '0')}`);
  const captureOf = pods => ({id: made, number: 9, cluster: 'c', namespace: 'n', workload: 'Deployment/w', requester: 'someone', state: 'Completed', createdAt: new Date().toISOString(), recordings: kinds.map(kind => ({kind})),
    tasks: pods.map((pod, i) => ({pod, node: 'node', state: 'Completed', recordings: kinds.map(kind => ({kind, state: i === 7 && kind === 'pcap' ? 'Failed' : 'Completed', message: i === 7 && kind === 'pcap' ? 'tcpdump said no' : ''}))})),
    artifacts: pods.flatMap(pod => [{name: pod + '/app.log', size: 100, sha256: 'a', recording: 'logs'}, {name: pod + '/pod.json', size: 100, sha256: 'a', recording: 'pod-state'}, {name: pod + '/capture.pcap', size: 100, sha256: 'a', recording: 'pcap'}])});
  const shown = () => run(`return [...document.querySelectorAll('.capture.open .file')].filter(f => f.offsetParent).length`);
  for (const [size, [width, height, mobile]] of Object.entries(widths)) await check(`${size}: a capture of many pods`, async () => {
    await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
    hostile = [[/^\/api\/captures(\?.*)?$/, [captureOf(podsOf(40))]]];
    await open(hub + '/#captures');
    await until('the list', `return document.querySelector('.capture')`);
    // Asked for anew: the page may be at the list already, with the capture of few pods.
    await run(`document.getElementById('captureFind').dispatchEvent(new Event('input'))`); await sleep(400);
    await run(`document.querySelector('.capture:not(.open) .chev')?.click()`); await sleep(200);
    if (await shown()) throw new Error(`${await shown()} files are listed before a pod is opened`);
    const tall = await run(`return document.querySelector('.capture.open').getBoundingClientRect().height`);
    if (tall > 3 * height) throw new Error(`the capture is ${Math.round(tall)} px tall, more than three screens`);
    // The line of a pod says what failed on it, and opens its files.
    if (!/failed|✗/.test(await run(`return document.querySelectorAll('.capture.open .podbox')[7].querySelector('.pod').innerText`))) throw new Error('the line of a pod does not say that a recording failed on it');
    await run(`document.querySelectorAll('.capture.open .podbox .pod')[7].click()`); await sleep(100);
    if (await shown() !== 3) throw new Error(`${await shown()} files are listed for the opened pod, want 3`);
    if (!/tcpdump said no/.test(await run(`return document.querySelectorAll('.capture.open .podbox')[7].innerText`))) throw new Error('the opened pod does not say why its recording failed');
    // It stays open when the list is written anew, with the keyboard still on its line, and closes again.
    await run(`document.querySelectorAll('.capture.open .podbox .pod')[7].focus()`);
    await run(`loadCaptures()`); await sleep(400);
    if (await shown() !== 3) throw new Error('the opened pod closed when the list was written anew');
    if (!await run(`return document.activeElement === document.querySelectorAll('.capture.open .podbox .pod')[7]`)) throw new Error('the keyboard left the line of the pod when the list was written anew');
    await run(`document.querySelectorAll('.capture.open .podbox .pod')[7].click()`); await sleep(100);
    if (await shown()) throw new Error('the pod did not close');
    // A few pods are shown with their files, as before.
    hostile = [[/^\/api\/captures(\?.*)?$/, [captureOf(podsOf(3))]]];
    await run(`document.getElementById('captureFind').dispatchEvent(new Event('input'))`); await sleep(400);
    if (await shown() !== 9) throw new Error(`${await shown()} files are listed for three pods, want 9`);
  });
  // A recording that found nothing to record has not failed: it stands as
  // done with what it found, and its capture says that it has no files.
  await check('desk: a recording that found nothing has not failed', async () => {
    await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
    const found = 'no sample fell on the pod\'s processes: they used about 30ms of CPU time in 30s, and a CPU is looked at 99 times a second. Record for longer, or while the pod is busy';
    const idle = {...captureOf(podsOf(1)), recordings: [{kind: 'cpu'}], artifacts: []};
    idle.tasks[0].recordings = [{kind: 'cpu', state: 'Completed', message: found}];
    hostile = [[/^\/api\/captures(\?.*)?$/, [idle]]];
    await run(`toggled.set(${JSON.stringify(made)}, true); await loadCaptures()`); await sleep(400);
    const shown = JSON.parse(await run(`const said = document.querySelector('.capture .rec .said'), line = document.querySelector('.capture .line');
      return JSON.stringify({said: said?.innerText || '', red: said ? getComputedStyle(said).color === getComputedStyle(document.querySelector('.problem') || document.body).color : false, failed: !!document.querySelector('.capture .rec-Failed'), line: line.innerText})`));
    if (!shown.said.includes('30ms of CPU time')) throw new Error(`the recording says "${shown.said}"`);
    if (shown.failed) throw new Error('a recording that found nothing is shown as failed');
    if (!/no files/.test(shown.line) || /failed/.test(shown.line)) throw new Error(`the capture's line reads "${shown.line.replace(/\n+/g, ' | ')}"`);
  });
  // What a recording was asked with is said in words: the endpoints of a
  // profile by their names and where they are, not by the catalog's IDs,
  // and a setting by what it means, not by its name in the request.
  await check('desk: the settings of a recording are said in words', async () => {
    await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
    const asked = {...captureOf(podsOf(1)), recordings: [{kind: 'pprof', params: {endpoints: '6060/go-cpu,6060/go-heap,app/jvm-threads'}}, {kind: 'pcap', params: {payload: 'true', filter: 'tcp port 80', before: 'true'}},
      {kind: 'logs', params: {previous: 'true', tailLines: '200', container: 'app'}}, {kind: 'strace', params: {strings: 'true'}}]};
    asked.tasks[0].recordings = asked.recordings.map(r => ({kind: r.kind, state: 'Completed'}));
    hostile = [[/^\/api\/captures(\?.*)?$/, [asked]]];
    await run(`toggled.set(${JSON.stringify(made)}, true); await loadCaptures()`); await sleep(400);
    const said = await run(`return [...document.querySelectorAll('.capture .given')].map(g => g.innerText).join(' | ')`);
    for (const want of ['CPU profile and Heap on port 6060', 'Thread dump in app', 'full packets', 'filter tcp port 80', 'the last 200 lines', 'before the last restart', 'container app', 'with the data read and written'])
      if (!said.includes(want)) throw new Error(`the settings read "${said}", without "${want}"`);
    for (const raw of ['go-cpu', 'endpoints', 'payload', 'tailLines', 'previous', 'strings', 'true'])
      if (said.includes(raw)) throw new Error(`the settings read "${said}", with "${raw}" as it is in the request`);
  });
  // The button of a capture's line that is the thing to do, as "Stop and
  // keep", is filled like every such button: without its ground, its dark
  // words stood on the dark page of a dark system and were hardly read.
  await check('dark: the button to stop a capture can be read', async () => {
    await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
    await send('Emulation.setEmulatedMedia', {features: [{name: 'prefers-color-scheme', value: 'dark'}]});
    // Its requester's to stop: this user's.
    const running = {id: made, number: 9, cluster: 'c', namespace: 'n', workload: 'Deployment/w', requester: await run(`return me.name`), state: 'Running', createdAt: new Date().toISOString(), durationSeconds: 600, remainingSeconds: 500,
      recordings: [{kind: 'pcap'}], tasks: [{pod: 'p', node: 'node', state: 'Running', recordings: [{kind: 'pcap', state: 'Running'}]}], artifacts: []};
    hostile = [[/^\/api\/captures(\?.*)?$/, [running]]];
    await open(hub + '/#captures');
    await until('the list', `return !document.getElementById('app').hidden`);
    await run(`loadCaptures()`); await sleep(400);
    // The luminance of the words against that of what they stand on (WCAG): 4.5 to 1 reads.
    const contrast = await run(`const b = [...document.querySelectorAll('.capture .acts button')].find(b => /Stop and keep/.test(b.innerText)); if (!b) return 0;
      const rgb = c => { const m = c.match(/[\\d.]+/g).map(Number); return m.length > 3 && m[3] === 0 ? null : m.slice(0, 3); };
      let ground = null; for (let e = b; e && !ground; e = e.parentElement) ground = rgb(getComputedStyle(e).backgroundColor);
      const lum = c => { const [r, g, bl] = c.map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * bl; };
      const a = lum(rgb(getComputedStyle(b).color)), g = lum(ground || [255, 255, 255]); return (Math.max(a, g) + 0.05) / (Math.min(a, g) + 0.05)`);
    await send('Emulation.setEmulatedMedia', {features: []});
    if (!contrast) throw new Error('no button to stop the capture');
    if (contrast < 4.5) throw new Error(`"Stop and keep" stands out by ${contrast.toFixed(1)} to 1, less than 4.5`);
  });
  // Who may approve in a namespace, and is no administrator, is shown what
  // waits for them above their own captures, and decides it there.
  const waiting = {captures: [{id: made, number: 12, cluster: 'c', namespace: 'payments', workload: 'Deployment/api', requester: 'alice', reason: 'the api hangs after the deploy', state: 'PendingApproval', recordings: [{kind: 'coredump'}], approvals: []}],
    watches: [{id: made, cluster: 'c', namespace: 'payments', workload: 'Deployment/a-workload-with-a-long-name-that-has-to-wrap-on-a-phone', requester: 'bob', reason: '', when: {kind: 'crash'}, recordings: [{kind: 'coredump'}], approvals: []}]};
  for (const [size, [width, height, mobile]] of Object.entries(widths)) await check(`${size}: requests that await this user's approval`, async () => {
    await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
    hostile = [[/^\/api\/approvals$/, waiting], [/^\/api\/captures(\?.*)?$/, []]];
    await open(hub + '/#captures');
    await until('the list', `return !document.getElementById('app').hidden`);
    // An administrator decides in the list itself, where every request that waits is shown: this is for who is none.
    if (await run(`return me.admin`)) return;
    await run(`loadCaptures()`); await sleep(400);
    const said = await run(`const a = document.getElementById('approvals'); return a.hidden ? '' : a.innerText`);
    for (const word of ['Awaiting your approval', 'alice', 'capture 0012', 'the api hangs after the deploy', 'payments', 'bob', 'a watch', 'No reason given']) {
      // The heading is shown in capitals.
      if (!said.toLowerCase().includes(word.toLowerCase())) throw new Error(`what awaits approval does not say "${word}": ${said}`);
    }
    const buttons = await run(`return [...document.querySelectorAll('#approvals button')].map(b => b.dataset.act + ' ' + b.dataset.path).join(', ')`);
    if (buttons !== 'approve captures, deny captures, approve watches') throw new Error('the decisions offered: ' + buttons);
    // With nothing to decide there is nothing of it.
    hostile = [[/^\/api\/approvals$/, {captures: [], watches: []}], [/^\/api\/captures(\?.*)?$/, []]];
    await run(`loadCaptures()`); await sleep(400);
    if (!await run(`return document.getElementById('approvals').hidden`)) throw new Error('an empty list of approvals is shown');
  });
  await send('Fetch.disable');
  // A watch is a line of the table at a desk: when it was made, its target
  // and how often it still records stand on one line each, and what is long,
  // the condition and the reason, takes the room that is left. The page
  // leads to the captures that it says appear.
  await check('desk: a watch is a line of its table', async () => {
    await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
    await open(hub + '/#watches');
    await until('the watches', `return !document.getElementById('app').hidden && !document.querySelector('[data-view=watches]').hidden`);
    const watch = {id: 'w1', cluster: 'production-eu', namespace: 'payments', workload: 'Deployment/payment-gateway', requester: 'someone', createdAt: new Date(2026, 10, 28, 20, 43, 57).toISOString(), remaining: 2,
      recordings: [{kind: 'pod-state'}, {kind: 'logs'}], durationSeconds: 30, reason: 'the gateway loses connections to the ledger every few hours', when: {kind: 'log', params: {pattern: 'connection (reset|refused) by ledger'}}};
    const lines = JSON.parse(await run(`const real = window.fetch;
      window.fetch = (url, options) => String(url).endsWith('/api/watches') ? Promise.resolve(new Response(${JSON.stringify(JSON.stringify([watch]))}, {headers: {'Content-Type': 'application/json'}})) : real(url, options);
      try { await loadWatches(); } finally { window.fetch = real; }
      const line = parseFloat(getComputedStyle(document.querySelector('#watches td')).lineHeight) || 20, cells = document.querySelectorAll('#watches tr td');
      const of = (node) => { const r = document.createRange(); r.selectNodeContents(node); return Math.round(r.getBoundingClientRect().height / line); };
      const out = {made: of(cells[0].firstChild), workload: of(cells[1].lastChild), head: Math.round(document.querySelector('#watchTable th:nth-child(5)').getBoundingClientRect().height),
        wide: document.getElementById('watchTable').scrollWidth > document.getElementById('watchTable').clientWidth + 1, link: document.querySelector('[data-view=watches] .lead a')?.getAttribute('href') || ''};
      await loadWatches(); return JSON.stringify(out)`));
    if (lines.made > 1 || lines.workload > 1) throw new Error(`a watch's date stands on ${lines.made} lines and its workload on ${lines.workload}`);
    if (lines.head > 40) throw new Error(`the heading "Times left" is ${lines.head} px high: broken into lines`);
    if (lines.wide) throw new Error('the table of watches is wider than its page');
    // Names as long as Kubernetes allows break and do not make the table wider than its page.
    const long = {...watch, id: 'w2', cluster: 'c'.repeat(60), namespace: 'n'.repeat(63), workload: 'Deployment/' + 'w'.repeat(120)};
    const wide = await run(`const real = window.fetch;
      window.fetch = (url, options) => String(url).endsWith('/api/watches') ? Promise.resolve(new Response(${JSON.stringify(JSON.stringify([watch, long]))}, {headers: {'Content-Type': 'application/json'}})) : real(url, options);
      try { await loadWatches(); } finally { window.fetch = real; }
      const wide = document.documentElement.scrollWidth > innerWidth + 1; await loadWatches(); return wide`);
    if (wide) throw new Error('a watch with long names makes the page wider than the window');
    if (lines.link !== '#captures') throw new Error(`the page says the captures appear under Captures and leads to "${lines.link}"`);
  });
  hostile = [];
}
if (adminToken) {
  await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
  await check('desk: an administrator signing in', async () => {
    signedOut = true;
    await open(hub + '/');
    await run(`sessionStorage.clear(); document.cookie = 'asservat_token=; path=/; max-age=0'; location.reload()`);
    await until('the sign-in form', `return !document.getElementById('login').hidden`);
    signedOut = false;
    await run(`sessionStorage.setItem('token', ${JSON.stringify(adminToken)}); location.reload()`);
    await until('the list of everyone\'s captures', `return !document.getElementById('app').hidden && document.querySelector('.capture')`);
    await run(`document.querySelector('.capture .where')?.click()`); await sleep(300);
  });
  for (const [size, [width, height, mobile]] of Object.entries(widths)) await check(`${size}: the audit log`, async () => {
    await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
    await run(`location.hash = '#audit'`);
    await until('entries of the audit log', `return !document.querySelector('[data-view=audit]').hidden && document.querySelectorAll('#auditRows tr').length > 0`);
    // An entry says who did what to which capture without scrolling sideways.
    const cut = await run(`return [...document.querySelectorAll('#auditRows td')].some(cell => cell.textContent.trim() && cell.getBoundingClientRect().right > innerWidth + 1)`);
    if (cut) throw new Error('an entry of the audit log reaches beyond the screen');
    // A page of a hundred was shown: the next one is asked for.
    await run(`document.getElementById('auditOlder').offsetParent && document.getElementById('auditOlder').click()`); await sleep(500);
  });
  // The audit log follows what happens: an entry that is made while it is
  // shown goes on top without anyone asking for it. Paused, the list stands
  // still, says that something waits, and takes it up when it goes on.
  await check('desk: the audit log follows what happens, and can be held still', async () => {
    await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
    await run(`location.hash = '#audit'`);
    await until('entries of the audit log', `return document.querySelectorAll('#auditRows tr').length > 0`);
    const file = await run(`const list = await (await fetch('/api/captures', {headers: {Authorization: 'Bearer ' + sessionStorage.getItem('token')}})).json();
      const c = list.find(c => c.artifacts.some(a => a.size && a.size < 1e6)); if (!c) return '';
      return '/api/captures/' + c.id + '/artifacts/' + c.artifacts.find(a => a.size && a.size < 1e6).name.split('/').map(encodeURIComponent).join('/')`);
    if (!file) throw new Error('no small file to download for an entry');
    const download = `await (await fetch(${JSON.stringify(file)}, {headers: {Authorization: 'Bearer ' + sessionStorage.getItem('token')}})).arrayBuffer()`;
    const top = () => run(`return document.querySelector('#auditRows tr')?.dataset.entry || ''`);
    const first = await top();
    await run(download);
    await until('the new entry on top', `return (document.querySelector('#auditRows tr')?.dataset.entry || '') !== ${JSON.stringify(first)}`, 10);
    if (!/downloaded a file/.test(await run(`return document.querySelector('#auditRows tr').innerText`))) throw new Error('the entry on top is not the download');
    // Held still.
    await run(`document.getElementById('auditLive').click()`);
    const held = await top();
    await run(download);
    await until('word of what waits', `return /1 new entry/.test(document.getElementById('auditLive').innerText)`, 10);
    if (await top() !== held) throw new Error('the paused audit log moved');
    if (!/Paused/.test(await run(`return document.getElementById('auditState').innerText`))) throw new Error('the paused audit log does not say that it is paused');
    await run(`document.getElementById('auditLive').click()`);
    await until('the entry that waited', `return (document.querySelector('#auditRows tr')?.dataset.entry || '') !== ${JSON.stringify(held)}`, 10);
    if (!/^Pause$/.test(await run(`return document.getElementById('auditLive').innerText.trim()`))) throw new Error('the audit log does not follow again');
    // Two entries at the same moment are two rows, each once.
    const before = await run(`return document.querySelectorAll('#auditRows tr').length`);
    await run(`await Promise.all([0, 1].map(async () => { ${download} }))`);
    await until('both entries', `return document.querySelectorAll('#auditRows tr').length >= ${before} + 2`, 10);
    await sleep(600);
    const rows = await run(`return [...document.querySelectorAll('#auditRows tr')].map(row => row.dataset.entry)`);
    if (new Set(rows).size !== rows.length || rows.length !== before + 2) throw new Error(`two entries at once made ${rows.length - before} rows, ${rows.length - new Set(rows).size} of them twice`);
  });
  // What the audit log names is a link to it: the capture, and the file
  // that was opened or downloaded. The capture's link leads to the capture
  // itself, open and in sight, also where it is far down the list.
  await check('desk: the audit log leads to what it names', async () => {
    await send('Emulation.setDeviceMetricsOverride', {width: 1400, height: 900, deviceScaleFactor: 1, mobile: false});
    await run(`location.hash = '#audit'`);
    await until('entries of the audit log', `return document.querySelectorAll('#auditRows tr').length > 0`);
    const named = JSON.parse(await run(`const file = [...document.querySelectorAll('#auditRows a[href^="/view?capture="]')].at(-1), capture = [...document.querySelectorAll('#auditRows a[href^="#capture="]')].at(-1);
      return JSON.stringify({file: file?.getAttribute('href') || '', capture: capture?.getAttribute('href') || ''})`));
    if (!named.capture) throw new Error('no entry of the audit log links to its capture');
    if (!/^\/view\?capture=[0-9a-f-]{36}&file=./.test(named.file)) throw new Error('no entry of the audit log links to its file: ' + named.file);
    const id = named.capture.slice('#capture='.length);
    await run(`document.querySelector('#auditRows a[href="${named.capture}"]').click()`);
    await until('the capture, open', `return !document.querySelector('[data-view=captures]').hidden && document.querySelector('.capture.open[data-capture="${id}"]')`);
    await sleep(400);
    const seen = await run(`const box = document.querySelector('.capture[data-capture="${id}"]').getBoundingClientRect(); return box.top < innerHeight && box.bottom > 0`);
    if (!seen) throw new Error('the capture that the audit log named is not in sight');
    // In its viewer, a file's capture is one step away.
    await open(hub + named.file);
    await until('the viewer', `return !document.getElementById('number').hidden`);
    const back = await run(`return document.getElementById('number').getAttribute('href')`);
    if (!/^\/#capture=[0-9a-f-]{36}$/.test(back || '')) throw new Error('the capture\'s number in the viewer leads to ' + back);
    await open(hub + '/#audit');
  });
}
ws.close();
// The browser writes into its profile until it has ended.
await new Promise(ended => { browser.on('exit', ended); browser.kill(); });
removed(profile);
if (failures.length) { console.error('\n' + failures.join('\n')); process.exit(1); }
