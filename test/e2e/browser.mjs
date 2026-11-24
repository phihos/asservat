// Opens the console and every viewer in a headless browser, as wide as a
// desk and as narrow as a phone, and fails on what a person would see as
// broken: a script's error, a failed request, a file that does not open, a
// page that runs out of the screen sideways. It drives Chromium over its
// DevTools protocol with what Node has, and needs no package.
//
//   node test/e2e/browser.mjs <hub URL> <token>
//
// $UNREADABLE names files, separated by commas, that are known not to be
// what their names say: of those the viewer must say that the hub could not
// open them. With $ONLY_NAMESPACES, a regular expression, it opens only the files of
// captures from namespaces that match: for a hub that holds more than tests.
//
// The browser is $CHROME, or the first of the usual names that is installed.
import {spawn, spawnSync} from 'node:child_process';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

const [hub, token] = process.argv.slice(2);
const chrome = process.env.CHROME || ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'].find(name => spawnSync('sh', ['-c', `command -v ${name}`]).status === 0);
if (!hub || !token) { console.error('usage: browser.mjs <hub URL> <token>'); process.exit(2); }
if (!chrome) { console.error('no Chromium or Chrome is installed'); process.exit(3); }

const profile = mkdtempSync(join(tmpdir(), 'asservat-browser-'));
const env = {...process.env}; delete env.LD_LIBRARY_PATH;
const browser = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], {env, stdio: ['ignore', 'ignore', 'pipe']});
// Chromium says on its standard error where its DevTools listen.
const listening = await new Promise((found, failed) => {
  let said = '';
  browser.stderr.on('data', d => { said += d; const m = /DevTools listening on ws:\/\/([^/]+)\//.exec(said); if (m) found(m[1]); });
  browser.on('exit', code => failed(new Error(`the browser ended with ${code}: ${said.slice(-400)}`)));
  setTimeout(() => failed(new Error('the browser did not start: ' + said.slice(-400))), 30000);
});
const sleep = ms => new Promise(r => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) { target = (await (await fetch(`http://${listening}/json`)).json()).find(t => t.type === 'page'); if (!target) await sleep(100); }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let id = 0, seen = [];
const waiting = new Map();
ws.onmessage = m => {
  const d = JSON.parse(m.data);
  if (d.id) { waiting.get(d.id)?.(d); waiting.delete(d.id); }
  else if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') seen.push('console: ' + d.params.args.map(a => a.value ?? a.description).join(' '));
  else if (d.method === 'Runtime.exceptionThrown') seen.push('exception: ' + (d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text));
  // Before signing in the console asks who is there and is told nobody.
  else if (d.method === 'Network.responseReceived' && d.params.response.status >= 400 && !d.params.response.url.endsWith('/api/me')) seen.push(`HTTP ${d.params.response.status} ${d.params.response.url}`);
};
const send = (method, params = {}) => new Promise(r => { waiting.set(++id, r); ws.send(JSON.stringify({id, method, params})); });
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
  for (const problem of new Set(seen)) failures.push(`${name}: ${problem}`);
  console.log(`${seen.length ? 'FAIL' : 'ok  '} ${name}`);
};
const open = async url => { await send('Page.navigate', {url}); await until('the page', `return document.readyState === 'complete'`); };

for (const [size, [width, height, mobile]] of Object.entries(widths)) {
  await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile});
  await check(`${size}: signing in`, async () => {
    await open(hub + '/');
    // As someone who has not signed in, also the second time round.
    await run(`sessionStorage.clear(); document.cookie = 'asservat_token=; path=/; max-age=0'; location.reload()`);
    await until('the sign-in form', `return !document.getElementById('login').hidden`);
    await run(`sessionStorage.setItem('token', ${JSON.stringify(token)}); location.reload()`);
    await until('the list of captures', `return !document.getElementById('app').hidden && document.querySelector('.capture, #noCaptures:not([hidden])')`);
  });
  for (const view of ['captures', 'watches', 'clusters']) await check(`${size}: ${view}`, async () => {
    await run(`location.hash = '#${view}'`);
    await until('the page ' + view, `return !document.querySelector('[data-view=${view}]').hidden`);
    if (view === 'captures') { await run(`document.querySelector('.capture .where')?.click()`); await sleep(300); }
  });
  await check(`${size}: a new capture, step by step`, async () => {
    await run(`location.hash = '#new'`);
    await until('a workload to choose', `return document.getElementById('workload').options.length > 0`);
    const next = `[...document.querySelectorAll('[data-view=new] button')].find(b => b.offsetParent && /Next/.test(b.innerText))?.click()`;
    await run(next); await sleep(300);
    // Every recording but the profile endpoint, which needs an endpoint chosen.
    await run(`for (const box of document.querySelectorAll('input[name=kind]')) if (!box.checked && box.value !== 'pprof') box.click()`);
    await run(next); await sleep(1500);
    await run(next); await sleep(300);
    await until('the last step', `return !!document.querySelector('input[name=when]')?.offsetParent`);
    // Every way to start shows its own fields.
    const ways = await run(`return [...document.querySelectorAll('input[name=when]')].map(i => i.value)`);
    for (const way of ways) { await run(`document.querySelector('input[name=when][value="${way}"]').click()`); await sleep(50); }
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
    for (const tab of tabs) { await run(`document.querySelector('#root [data-tab="${tab}"]').click()`); await sleep(150); }
    await run(`document.querySelector('#root .row, #root .c, #root .l, #root .g')?.click()`); await sleep(150);
  });
}
ws.close();
// The browser writes into its profile until it has ended.
await new Promise(ended => { browser.on('exit', ended); browser.kill(); });
try { rmSync(profile, {recursive: true, force: true, maxRetries: 5, retryDelay: 200}); } catch {}
if (failures.length) { console.error('\n' + failures.join('\n')); process.exit(1); }
