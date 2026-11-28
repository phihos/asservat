// The console: everything the page at / does. It is a file of its own so
// that the page can tell the browser to run no script from its markup.
const $ = id => document.getElementById(id);
let me = null;
const token = () => sessionStorage.getItem('token') || '';
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

async function call(method, path, body) {
  // Without a token the browser's single sign-on session applies.
  const res = await fetch(path, {method, headers: {...(token() ? {Authorization: 'Bearer ' + token()} : {}), ...(body ? {'Content-Type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined});
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(data?.error || res.statusText);
  return data;
}
// A failure is shown where it happened: every action names the element for
// its message, next to what the user just used.
const guard = (f, at = 'error') => async e => {
  // Only a form's own submit is replaced; a click on a link, such as a file to download, takes its course.
  if (e?.type === 'submit') e.preventDefault();
  $(at).textContent = '';
  try { await f(e); } catch (err) { $(at).textContent = err.message; $(at).scrollIntoView({block: 'nearest', behavior: 'smooth'}); }
};

async function start() {
  try { me = await call('GET', '/api/me'); } catch { me = null; }
  $('login').hidden = !!me; $('app').hidden = !me; $('signout').hidden = !me;
  if (!me) { $('sso').hidden = !(await call('GET', '/api/login')).oidc; return; }
  // Downloads and the event stream cannot send a header.
  if (token()) document.cookie = 'asservat_token=' + token() + '; path=/; SameSite=Strict';
  $('me').textContent = me.name + (me.admin ? ' (administrator)' : '');
  // For someone who approves their own requests, the badges only inform.
  document.body.classList.toggle('own', !!me.selfApproval);
  for (const badge of document.querySelectorAll('.badge')) badge.textContent = badgeText();
  $('nav').hidden = $('newButton').hidden = false;
  $('auditNav').hidden = !me.admin;
  route();
  await Promise.all([loadClusters(), loadCaptures(), loadWatches()]);
  comeBack();
  new EventSource('/api/events').onmessage = guard(() => Promise.all([loadCaptures(), loadWatches()]));
}

// Who comes back with the browser's own way back, as from a file's viewer,
// or loads the page anew, finds the page where it stood. The browser cannot put it there itself:
// the lists are filled after the page has loaded.
history.scrollRestoration = 'manual';
addEventListener('pagehide', () => { try { sessionStorage.setItem('stood', JSON.stringify({at: scrollY, view: location.hash})); } catch { /* then it starts at the top */ } });
function comeBack() {
  // Also after a reload, which the browser would have put back itself.
  if (!['back_forward', 'reload'].includes(performance.getEntriesByType('navigation')[0]?.type)) return;
  try {
    const stood = JSON.parse(sessionStorage.getItem('stood') || 'null');
    if (stood && stood.view === location.hash) scrollTo(0, stood.at);
  } catch { /* then it starts at the top */ }
}

// One view at a time, named by the address: #captures, #new, #watches, #clusters.
// sought is the capture that an address names (#capture=<id>), until the
// list has shown it: it is opened and brought into sight.
let sought = '';
function route() {
  const views = [...document.querySelectorAll('[data-view]')].map(v => v.dataset.view);
  const named = location.hash.startsWith('#capture=') ? decodeURIComponent(location.hash.slice(9)) : '';
  const view = views.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'captures';
  if (named) {
    sought = named;
    toggled.set(named, true);
    // Whatever narrows the list could hide it.
    captureFilter = 'all'; $('captureFind').value = '';
    for (const b of $('states').children) b.classList.toggle('on', b.dataset.filter === 'all');
  }
  for (const v of document.querySelectorAll('[data-view]')) v.hidden = v.dataset.view !== view;
  for (const a of document.querySelectorAll('[data-nav]')) a.classList.toggle('on', a.dataset.nav === view);
  $('newButton').hidden = !me || view === 'new';
  if (view === 'new') showStep(step);
  if (view === 'audit' && me?.admin) guard(() => loadAudit(true), 'auditProblem')();
}
// A capture that an address names while the page is open is looked for at
// once. At the start the list is loaded anyway, once, and finds it.
window.onhashchange = () => { route(); if (sought && me) guard(loadCaptures, 'capturesProblem')(); };

async function loadClusters() {
  const clusters = await call('GET', '/api/clusters');
  $('clusterList').innerHTML = clusters.map(c => `<tr><td>${esc(c.name)}</td><td>${c.nodes.length ? c.nodes.map(esc).join(', ') : '<span class="muted">None. No agent of this cluster is connected.</span>'}</td></tr>`).join('')
    || '<tr><td colspan="2" class="muted">No clusters yet.</td></tr>';
  const selected = $('cluster').value;
  $('cluster').innerHTML = clusters.map(c => `<option>${esc(c.name)}</option>`).join('');
  if (selected) $('cluster').value = selected;
  else await loadNamespaces();
}

// Everything that exists in the cluster is offered, never typed: each list
// follows the choice before it.
const options = list => list.map(v => `<option>${esc(v)}</option>`).join('');
const namespacePath = () => `/api/clusters/${encodeURIComponent($('cluster').value)}/namespaces/${encodeURIComponent($('namespace').value)}`;
const workloadQuery = () => 'workload=' + encodeURIComponent($('workload').value);
const target = () => [$('cluster').value, $('namespace').value, $('workload').value].join('/');
const picked = name => document.querySelector(`input[name=${name}]:checked`).value;
const size = bytes => bytes >= 1 << 30 ? (bytes / (1 << 30)).toFixed(1) + ' GiB' : Math.max(1, Math.round(bytes / (1 << 20))) + ' MiB';
const fileSize = bytes => bytes < 1024 ? bytes + ' B' : bytes < 1 << 20 ? Math.round(bytes / 1024) + ' KiB' : size(bytes);
// Who approves a sensitive request here: one administrator, or as many as the installation asks for.
const approvers = () => me?.approvalsNeeded > 1 ? `${me.approvalsNeeded} administrators approve` : 'An administrator approves';
const badgeText = () => me?.selfApproval ? 'sensitive' : 'needs approval';
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

async function loadNamespaces() {
  $('namespace').innerHTML = $('workload').innerHTML = '';
  if ($('cluster').value) $('namespace').innerHTML = options(await call('GET', `/api/clusters/${encodeURIComponent($('cluster').value)}/namespaces`));
  // An empty list says nothing by itself: who may capture nowhere is told why.
  $('nowhere').hidden = !$('cluster').value || !!$('namespace').value;
  await loadWorkloads();
}

async function loadWorkloads() {
  $('workload').innerHTML = '';
  if ($('namespace').value) $('workload').innerHTML = options(await call('GET', namespacePath() + '/workloads'));
  await workloadChanged();
}

// What was learned about a workload belongs to that workload only.
let containers = [], processesOf = '', profilesOf = '', flows = [];
async function workloadChanged() {
  containers = []; processesOf = profilesOf = '';
  $('container').innerHTML = $('process').innerHTML = $('profileChoices').innerHTML = $('profilePort').innerHTML = '';
  $('profileState').textContent = $('profilePath').value = '';
  showFlows(null);
  if (!$('workload').value) return;
  containers = await call('GET', namespacePath() + '/containers?' + workloadQuery());
  $('container').innerHTML = '<option value="">all containers</option>' + options(containers);
  $('logContainer').innerHTML = $('usageContainer').innerHTML = '<option value="">any container</option>' + options(containers);
  await Promise.all([loadProcesses(), loadProfiles()]);
}

// The profile endpoints are looked for in a pod when a profile is chosen.
async function loadProfiles() {
  const of = target();
  if (!kinds().includes('pprof') || !$('workload').value || profilesOf === of) return;
  profilesOf = of;
  $('profileChoices').innerHTML = '';
  $('profileState').className = 'muted';
  $('profileState').textContent = 'Looking for profile endpoints on the pod\'s ports…';
  let found;
  try { found = await call('POST', namespacePath() + '/profiles?' + workloadQuery()); } catch (err) {
    if (of !== target()) return;
    $('profileState').className = 'problem';
    $('profileState').textContent = `Could not look for profile endpoints: ${err.message}`;
    $('otherEndpoint').open = true;
    return showParams();
  }
  if (of !== target()) return; // another workload was chosen meanwhile
  const ports = found.ports || [];
  found.profiles ||= []; // left out when nothing was found
  $('profilePort').innerHTML = options(ports);
  // One group per runtime and port, or container for a JVM's own
  // diagnostics. The first profile over time is ticked; a JVM's
  // diagnostics are not, since they write into the container and signal.
  const groups = {}, where = p => p.container || p.port, served = found.profiles.filter(p => !p.container);
  for (const p of found.profiles) (groups[`${p.runtime} ${p.container ? 'in container' : 'on port'} ${where(p)}`] ||= []).push(p);
  const first = served.find(p => p.timed && !p.sensitive) || served.find(p => !p.sensitive);
  $('profileChoices').innerHTML = Object.entries(groups).map(([title, list]) => `<div class="group"><div>${esc(title)}</div>${list.map(p =>
    `<label><input type="checkbox" data-endpoint="${esc(where(p))}/${esc(p.endpoint)}" ${p.timed ? 'data-timed' : ''} ${p.sensitive ? 'data-sensitive' : ''} ${p === first ? 'checked' : ''}>${esc(p.name)}${
      p.sensitive ? `<span class="badge">${badgeText()}</span>` : ''}${p.timed ? '<span class="muted">runs for the time frame</span>' : ''}</label>`).join('')}</div>`).join('');
  $('profileState').textContent = (found.profiles.length ? 'Found on the pod. Tick what to record; everything ticked is taken at once.'
    : `No known profile endpoint answers on ${ports.length ? `the pod's ${plural(ports.length, 'port')} (${ports.join(', ')})` : 'the pod, which listens on no TCP port'}. `
      + 'Asservat recognises Go (net/http/pprof, also served by libraries for other languages), C and C++ with gperftools or brpc, Java with Spring Boot Actuator, and .NET with dotnet-monitor. It asks a HotSpot JVM directly.'
      + (ports.length ? ' If the application serves a different endpoint, enter it below.' : '')
      + ' Without an endpoint, "CPU profile" and "Memory growth" in the previous step record from outside the application.')
    + (found.notes || []).map(note => ' ' + note).join('');
  $('otherEndpoint').open = !found.profiles.length && ports.length > 0;
  showParams();
}
const profileBoxes = () => [...document.querySelectorAll('#profileChoices input:checked')];
// What the profile recording asks for: found endpoints, or another one.
function profileParams() {
  const ticked = profileBoxes(), path = $('profilePath').value.trim();
  if (ticked.length && path) throw new Error('Either tick endpoints above or enter a different endpoint, not both.');
  if (ticked.length) return {endpoints: ticked.map(box => box.dataset.endpoint).join(',')};
  if (path && $('profilePort').value) return {port: $('profilePort').value, path};
  throw new Error($('profileChoices').innerHTML ? 'Tick at least one profile, or untick "Profile endpoint" in the previous step.' : 'No profile endpoint is selected. Enter one under "Use a different endpoint", or untick "Profile endpoint" in the previous step.');
}

const kinds = () => [...document.querySelectorAll('input[name=kind]:checked')].map(box => box.value);
const kindNames = {'pod-state': 'pod state', logs: 'logs', pcap: 'network traffic', strace: 'system calls', pprof: 'profile endpoint', cpu: 'CPU profile', memory: 'memory growth', coredump: 'core dump'};
const list = words => words.length < 2 ? words.join('') : words.slice(0, -1).join(', ') + ' and ' + words.at(-1);
// A core dump on a crash is that of the crashed process: nothing to choose.
const wantsProcess = () => kinds().includes('strace') || kinds().includes('coredump') && picked('when') !== 'crash';
// What a watch can wait for, as the end of a sentence.
const conditions = {crash: 'when a container crashes', restart: 'when a container restarts', 'not-ready': 'when the pod becomes unready', log: 'when a log line matches',
  memory: 'when memory use is above', cpu: 'when CPU use is above', throttled: 'when CPU is throttled for more than', alert: 'when the alert fires:', event: 'when Kubernetes reports a warning', time: 'at', asked: 'when asked',
  'memory-growth': 'when memory grows by more than', pressure: 'when it stalls for more than', threads: 'when it has more threads than', 'open-files': 'when it has more open files than',
  'tcp-retransmits': 'when TCP retransmits per second exceed', 'tcp-failures': 'when failed TCP connections per second exceed'};
// The thresholds a usage condition takes, as an example in its field.
const thresholds = {memory: '80% of the limit, or 500Mi', cpu: '1.5 CPUs, or 90% of the limit', throttled: '25% of the time', 'memory-growth': '100Mi', pressure: '20% of the time',
  threads: '500', 'open-files': '1000', 'tcp-retransmits': '10 per second', 'tcp-failures': '1 per second'};
// A watch's condition in full, with what it is given.
function told(when) {
  const given = when?.params || {}, where = given.container ? ' in ' + given.container : '';
  return (conditions[when?.kind] || when?.kind || '') + (when?.kind === 'log' ? ` "${given.pattern || ''}"${where}`
    : when?.kind in thresholds ? ` ${given.above}${given.of ? ' for ' + given.of : ''}${given.seconds > 0 ? ` ${when.kind === 'memory-growth' ? 'within' : 'for'} ${given.seconds} s` : ''}${where}` : when?.kind === 'alert' ? ` ${given.name || ''}` : when?.kind === 'event' ? (given.reason ? ': ' + given.reason : '')
    : when?.kind === 'time' ? ` ${new Date(given.at).toLocaleString()}${given.every ? `, again every ${Math.round(given.every / 60)} min` : ''}` : '');
}
// The condition that the form's last step describes.
function condition() {
  const kind = picked('when');
  if (kind === 'log') {
    const pattern = $('logPattern').value.trim();
    if (!pattern) throw new Error('Enter the pattern a log line has to match.');
    return {kind, params: {pattern, ...($('logContainer').value ? {container: $('logContainer').value} : {})}};
  }
  if (kind in thresholds) {
    const above = $('usageAbove').value.trim().replace(/\s+/g, '');
    if (!above) throw new Error(`Enter a threshold: ${thresholds[kind]}.`);
    if (kind === 'memory-growth' && !($('usageSeconds').value > 0)) throw new Error('Enter the number of seconds within which memory grows by that much.');
    return {kind, params: {above, ...(kind === 'pressure' ? {of: $('usageOf').value} : {}), ...($('usageSeconds').value > 0 ? {seconds: String(Math.round($('usageSeconds').value))} : {}), ...($('usageContainer').value ? {container: $('usageContainer').value} : {})}};
  }
  if (kind === 'event') {
    const reason = $('eventReason').value.trim();
    return {kind, params: reason ? {reason} : {}};
  }
  if (kind === 'time') {
    const at = new Date($('timeAt').value);
    if (isNaN(at)) throw new Error('Enter the time to record at.');
    return {kind, params: {at: at.toISOString().replace(/\.\d+Z$/, 'Z'), ...($('timeEvery').value > 0 ? {every: String(Math.round($('timeEvery').value * 60))} : {})}};
  }
  if (kind === 'alert') {
    const name = $('alertName').value.trim();
    if (!name) throw new Error('Enter the name of the alert.');
    return {kind, params: {name}};
  }
  return {kind};
}

// The process list is read from the pods when a core dump or trace is
// chosen. If that fails, the containers' main processes remain as choices.
async function loadProcesses() {
  const of = target();
  if (!wantsProcess() || !$('workload').value || processesOf === of) return;
  processesOf = of;
  $('process').innerHTML = '<option>Looking at the running processes…</option>';
  $('process').disabled = true;
  $('processHint').textContent = '';
  let found = {pods: [], processes: []}, problem = '';
  try { found = await call('GET', namespacePath() + '/processes?' + workloadQuery()); } catch (err) { problem = err.message; }
  if (of !== target()) return; // another workload was chosen meanwhile
  found.processes ||= []; // left out when nothing runs
  const groups = [];
  for (const container of found.processes.length ? [...new Set(found.processes.map(p => p.container))] : containers) {
    const programs = found.processes.filter(p => p.container === container);
    const main = programs.find(p => p.main);
    const choice = (value, text, p) => `<option value="${esc(JSON.stringify(value))}" data-bytes="${p?.largestResidentBytes || 0}" data-count="${p ? Math.ceil(p.processes / p.pods) : 1}">${esc(text)}</option>`;
    let options = choice({container}, main ? `Main process: ${main.name}` : 'Main process', main && {...main, processes: main.pods});
    for (const p of programs) {
      // A program that only runs as the main process is that choice already.
      if (p.main && p.processes === p.pods) continue;
      const count = p.processes === p.pods ? 'one per pod' : p.pods === 1 ? plural(p.processes, 'process') + ' in the pod' : `${plural(p.processes, 'process')} in ${plural(p.pods, 'pod')}`;
      options += choice({container, process: p.executable}, `Every ${p.name} process: ${p.executable} (${count})`, p);
    }
    groups.push(`<optgroup label="Container ${esc(container)}">${options}</optgroup>`);
  }
  $('process').innerHTML = groups.join('');
  $('process').disabled = false;
  $('process').dataset.note = problem ? `Could not list the processes (${problem}), so only the main processes are offered. `
    : found.notInspected?.length ? `${plural(found.notInspected.length, 'pod')} could not be inspected: no agent is connected on their node, or the pod is restarting. ` : '';
  showParams();
}

function processHint() {
  const chosen = $('process').selectedOptions[0], dump = kinds().includes('coredump') && picked('when') === 'now';
  let text = $('process').dataset.note || '';
  if (dump && chosen) {
    const bytes = Number(chosen.dataset.bytes), count = Number(chosen.dataset.count);
    if (bytes) text += `A core dump is about as large as the process's memory: ${size(bytes)}${count > 1 ? ` each, ${count} per pod` : ''}. `;
    text += 'The process pauses while the core dump is written. ';
  }
  if (kinds().includes('strace')) text += dump ? 'The trace starts once the core dump is written and slows the process down while it runs.' : 'Tracing slows the process down while it runs.';
  return text;
}

// The traffic sample: what the pods talk to right now, as rows to tick.
function showFlows(sample) {
  flows = sample?.flows || [];
  $('flowTable').hidden = !flows.length;
  $('filter').value = '';
  const most = Math.max(1, ...flows.map(f => f.bytes));
  const arrows = {in: ['←', 'incoming'], out: ['→', 'outgoing'], local: ['↻', 'inside the pod']};
  $('flows').innerHTML = flows.map((f, i) => {
    const notes = [sample.pods.length > 1 ? `${f.pods} of ${sample.pods.length} pods` : '',
      f.direction === 'out' && !f.peerName?.startsWith('Service') ? 'this address can change when the peer restarts' : ''].filter(Boolean).join(' · ');
    return `<tr><td><input type="checkbox" data-flow="${i}" aria-label="${esc(f.label)}"></td><td class="arrow" title="${arrows[f.direction][1]}">${arrows[f.direction][0]}</td>
      <td>${esc(f.label)}<div class="muted">${esc(notes)}</div></td><td>${f.packets.toLocaleString()}</td><td><div class="bar" style="width:${Math.round(100 * f.bytes / most)}%"></div></td></tr>`;
  }).join('');
  if (!sample) $('sampleState').textContent = 'Pick connections from what the pods are doing right now instead of writing a filter.';
  else {
    const where = `in ${plural(sample.seconds, 'second')} on ${plural(sample.pods.length, 'pod')}`;
    const missed = sample.notInspected?.length ? ` ${plural(sample.notInspected.length, 'pod')} could not be inspected: no agent is connected on their node, or the pod is restarting.` : '';
    $('sampleState').textContent = (flows.length ? `Seen ${where}. Tick the connections you want to record.` : `No packets ${where}. The workload may still have connections: sample again, or record all traffic.`) + missed;
  }
  filterChanged();
}

// Ticked rows become the filter. Typing a filter instead unticks them.
function filterChanged(typed) {
  const chosen = typed ? [] : [...document.querySelectorAll('#flows input:checked')].map(box => flows[box.dataset.flow]);
  if (typed) for (const box of document.querySelectorAll('#flows input:checked')) box.checked = false;
  else $('filter').value = chosen.length > 1 ? chosen.map(f => `(${f.filter})`).join(' or ') : chosen[0]?.filter || '';
  $('chosen').textContent = chosen.length ? 'Records only: ' + chosen.map(f => f.label).join('; ') + '.'
    : $('filter').value ? 'Records what the filter below matches.' : 'Records all traffic to and from the pods.';
}

function showParams() {
  const chosen = kinds(), crash = picked('when') === 'crash', watching = picked('when') !== 'now', has = kind => chosen.includes(kind);
  for (const el of document.querySelectorAll('[data-kinds]')) el.hidden = !el.dataset.kinds.split(' ').some(has);
  $('processBlock').hidden = !wantsProcess();
  $('processTitle').textContent = 'Process for the ' + list(['coredump', 'strace'].filter(k => has(k) && (k !== 'coredump' || !crash)).map(k => kindNames[k]));
  // A crash watch reads both log instances.
  $('instanceLabel').hidden = crash;
  $('processHint').textContent = processHint();
  // One time frame for everything that runs over time.
  const otherProfile = has('pprof') && !profileBoxes().length && $('profilePath').value.trim();
  const profileRuns = has('pprof') && (otherProfile || profileBoxes().some(box => 'timed' in box.dataset));
  const timed = ['pcap', 'strace', 'cpu', 'memory', 'pprof'].filter(k => has(k) && (k !== 'pprof' || profileRuns)), follows = has('logs');
  $('frameBlock').hidden = !timed.length && !follows;
  $('duration').placeholder = timed.length ? '30' : '0';
  // The packet buffer of a watch reaches back; everything else runs forward.
  const running = timed.filter(k => !(k === 'pcap' && crash)).map(k => kindNames[k]);
  $('frameHint').textContent = [
    watching ? 'Recordings that the last step keeps running also reach back before that moment, by this many seconds unless you set a number there.' : '',
    running.length ? `The ${list(running)} ${running.length > 1 ? 'recordings run' : 'recording runs'} this long${crash ? ' after the crash' : watching ? ' from that moment' : ''}.` : '',
    follows ? (timed.length ? 'Logs are followed for the same time.' : 'With 0, the logs are saved as they are. Otherwise they are followed for this long.') : '',
  ].filter(Boolean).join(' ');
  $('nothing').hidden = !(chosen.length === 1 && has('pod-state'));
  $('crashHint').textContent = !chosen.length ? '' : 'For the crashed pod: ' + list(chosen.map(k => ({
    pcap: 'the packets from before the crash', logs: 'the logs of the crashed container and of its replacement',
    coredump: 'the core dump of the crashed process (requires the agents\' core handler)', 'pod-state': 'the pod with the crash reason',
    strace: 'a trace of the restarted container', pprof: 'a profile of the restarted container',
    cpu: 'a CPU profile of the restarted container', memory: 'a memory growth profile of the restarted container'}[k])));
  $('countLabel').hidden = !watching;
  $('logFields').hidden = picked('when') !== 'log';
  $('usageFields').hidden = !(picked('when') in thresholds);
  $('alertFields').hidden = picked('when') !== 'alert';
  $('eventFields').hidden = picked('when') !== 'event';
  $('timeFields').hidden = picked('when') !== 'time';
  // What a watch can keep running, of what is chosen.
  for (const label of document.querySelectorAll('[data-before]')) label.hidden = !has(label.dataset.before);
  $('beforeFields').hidden = !watching || !['pcap', 'cpu', 'memory', 'strace'].some(has);
  $('usageAbove').placeholder = thresholds[picked('when')] || '';
  $('pressureOf').hidden = picked('when') !== 'pressure';
  $('usageSecondsLabel').textContent = picked('when') === 'memory-growth' ? 'Within (seconds)' : 'For at least (seconds)';
  $('usageSeconds').placeholder = picked('when') === 'memory-growth' ? '300' : '0 = as soon as it is seen';
  const sensitive = [has('coredump') && 'the core dump', has('pcap') && picked('payload') && 'full packets', has('strace') && picked('strings') && 'the data in system calls',
    has('pprof') && profileBoxes().some(box => 'sensitive' in box.dataset) && 'a memory dump', otherProfile && 'a custom endpoint'].filter(Boolean);
  $('approvalNotice').hidden = !sensitive.length;
  // Someone who may approve their own requests is not asked to.
  const asks = sensitive.length && !me?.selfApproval;
  $('approvalNotice').textContent = !sensitive.length ? '' : !asks
    ? `Sensitive because of ${list(sensitive)}. It starts right away because you may approve your own requests. The audit log records it as approved by you.`
    : `Needs approval because of ${list(sensitive)}. ` + (watching
      ? `${approvers()} the watch once, before it starts. Its captures then need no further approval.`
      : chosen.length > 1 ? `${approvers()} the whole request at once. Nothing starts before that.` : `It starts once ${approvers().toLowerCase().replace(/ approves?$/, '')} ${me?.approvalsNeeded > 1 ? 'have' : 'has'} approved it.`);
  // An installation can ask for the reason of every request that is sensitive.
  const must = !!(sensitive.length && me?.reasonRequired);
  $('reasonLabel').textContent = (asks ? 'Reason, shown to the approver' : 'Reason') + (must ? ' (required)' : '');
  $('reason').required = must;
  $('submit').textContent = watching ? (asks ? 'Request approval for this watch' : 'Start the watch') : asks ? 'Request approval' : 'Record now';
  $('done').textContent = $('formProblem').textContent = $('profileProblem').textContent = $('kindProblem').textContent = '';
  $('submit').disabled = false;
  if (!$('app').hidden) showStep(step);
}

const describe = c => (c.recordings || []).map(r => `<div>${esc(kindNames[r.kind] || r.kind)}<span class="muted"> ${esc(Object.entries(r.params || {}).map(([k, v]) => `${k}=${v}`).join(', '))}</span></div>`).join('')
  + `<div class="muted">${c.durationSeconds ? `${c.durationSeconds} s` : ''}${c.durationSeconds && c.reason ? ' · ' : ''}${esc(c.reason)}</div>`;

// The audit log, a page at a time, newest first. An action is said in words;
// its detail is what the hub recorded with it.
const auditActions = {'capture.request': 'requested a capture', 'capture.approve': 'approved a capture', 'capture.deny': 'denied a capture', 'capture.cancel': 'withdrew a capture',
  'capture.stop': 'stopped a capture', 'capture.share': 'shared a capture', 'capture.unshare': 'stopped sharing a capture', 'capture.delete': 'deleted a capture', 'capture.expire': 'capture expired', 'capture.trigger': 'a watch recorded',
  'watch.create': 'created a watch', 'watch.approve': 'approved a watch', 'watch.delete': 'deleted a watch',
  'artifact.download': 'downloaded a file', 'artifact.view': 'opened a file in a viewer', 'artifact.read': 'read a file over MCP', 'artifact.describe': 'had a core dump described again',
  'profile.discover': 'looked for profile endpoints', 'traffic.sample': 'sampled live traffic'};
const auditPage = 100;
let auditEntries = [];
async function loadAudit(fresh) {
  // A page begins where the last one ended: at its moment, below its entry.
  const last = auditEntries.at(-1), before = fresh || !last ? '' : `&before=${encodeURIComponent(last.at)}&beforeId=${last.id}`;
  const page = await call('GET', `/api/audit?limit=${auditPage}${before}`);
  auditEntries = fresh ? page : auditEntries.concat(page);
  // What an entry names is a link to it while it is there: the capture, its file, the watches.
  const linked = (e, k, v) => (k === 'name' || k === 'file') && e.number && typeof v === 'string' ? `<a href="/view?capture=${encodeURIComponent(e.capture)}&file=${encodeURIComponent(v)}" title="Look at the file">${esc(v)}</a>`
    : k === 'id' && e.action.startsWith('watch.') && e.action !== 'watch.delete' ? `<a href="#watches" title="The watches">${esc(v)}</a>` : esc(typeof v === 'object' ? JSON.stringify(v) : v);
  // A request reads as a sentence, not as the fields it was sent with: what
  // of which workload, for how long, on what condition, and why. What else
  // an entry holds follows as it is, without what only the hub needs.
  const aside = ['cluster', 'namespace', 'workload', 'recordings', 'kind', 'params', 'durationSeconds', 'reason', 'when', 'requester', 'selector', 'remaining', 'createdAt', 'sensitive', 'approver', 'approvals', 'groups', 'count', 'beforeSeconds'];
  const detail = (d, e) => {
    if (!d || typeof d !== 'object') return esc(d ?? '');
    const recorded = d.recordings?.length ? d.recordings : d.kind ? [{kind: d.kind}] : [];
    const said = [
      recorded.length ? esc(list2(recorded.map(r => kindNames[r.kind] || r.kind))) + (d.durationSeconds ? ` for ${d.durationSeconds} s` : '') : '',
      d.workload ? `${esc(d.workload)} in ${esc(d.cluster || '')} / ${esc(d.namespace || '')}` : '',
      d.when?.kind ? esc(told(d.when)) + (d.count > 1 ? `, ${d.count} times` : '') : '',
      d.reason ? `“${esc(d.reason)}”` : '',
      ...Object.entries(d).filter(([k, v]) => !aside.includes(k) && v !== '' && v != null && v !== false).map(([k, v]) => `${esc(k === 'name' ? 'file' : k)}: ${linked(e, k, v)}`),
    ];
    return said.filter(Boolean).join(' · ');
  };
  $('auditRows').innerHTML = auditEntries.map(e => `<tr><td class="when">${new Date(e.at).toLocaleString()}</td><td>${esc(e.actor || 'Asservat')}</td><td>${esc(auditActions[e.action] || e.action)}</td>
    <td>${e.capture ? (e.number ? `<a class="number" href="#capture=${encodeURIComponent(e.capture)}" title="Go to the capture"><b>${String(e.number).padStart(4, '0')}</b></a>` : `<span class="muted" title="${esc(e.capture)}">deleted or expired</span>`) : ''}</td><td class="muted">${detail(e.detail, e)}</td></tr>`).join('');
  $('auditTable').hidden = !auditEntries.length; $('noAudit').hidden = !!auditEntries.length;
  $('auditOlderLine').hidden = page.length < auditPage;
}

async function loadWatches() {
  const list = await call('GET', '/api/watches');
  $('watchTable').hidden = !list.length; $('noWatches').hidden = !!list.length;
  $('watchCount').textContent = list.length || '';
  $('watches').innerHTML = list.map(w => `<tr class="${freshClass(w.id)}" data-watch="${w.id}"><td>${new Date(w.createdAt).toLocaleString()}<div class="muted">${esc(w.requester)}</div></td>
    <td>${esc(w.cluster)} / ${esc(w.namespace)}<br>${esc(w.workload)}</td><td>${esc(told(w.when))}</td><td>${describe(w)}</td><td>${w.remaining}${w.sensitive ? `<div class="muted">${w.approver ? 'approved by ' + esc(w.approver) : `<span class="state PendingApproval">awaits approval</span>${approvalsOf(w) ? '<br>' + approvalsOf(w) : ''}`}</div>` : ''}</td>
    <td>${me.admin && w.sensitive && !w.approver && !approvedByMe(w) ? `<button data-id="${w.id}" data-act="approve">Approve</button>` : ''}${!w.sensitive || w.approver ? `<button data-id="${w.id}" data-act="record" title="Record all pods of the workload now. This counts as one of the watch's recordings.">Record now</button>` : ''}<button data-id="${w.id}">Delete</button></td></tr>`).join('');
}

// How a recording gets on, as a mark before its name.
// What a file is, for someone who did not name it.
const whatIs = name => name === 'capture.pcap' ? 'packet capture, for Wireshark' : name === 'pod.json' ? 'the pod object from Kubernetes' : name === 'events.json' ? 'the pod\'s events'
  : name.endsWith('.previous.log') ? 'container log from before the last restart' : name.endsWith('.log') ? 'container log' : name.endsWith('.strace') ? 'system call trace, in strace format'
  : name === 'sampled-cpu.pprof' ? 'CPU profile, for pprof' : name === 'sampled-memory.pprof' ? 'memory growth profile, for pprof'
  : name.endsWith('.analysis.json') ? 'description of the core dump: stacks and variables' : name.endsWith('.files.tar') ? 'program files a debugger needs alongside the core dump'
  : name.startsWith('core.') ? 'core dump, for gdb or Delve' : name.endsWith('.pprof') ? 'profile, for pprof' : name.endsWith('.hprof') ? 'Java heap dump' : name.endsWith('.jfr') ? 'Java flight recording; all of it opens in JDK Mission Control' : name.endsWith('threaddump.txt') ? 'stacks of all threads' : name.endsWith('histogram.txt') ? 'object counts and sizes by class' : name.endsWith('.nettrace') ? '.NET trace'
  : name.endsWith('.gcdump') ? '.NET heap summary' : name.endsWith('.dmp') ? '.NET memory dump' : name === 'trace.out' ? 'Go execution trace' : name === 'goroutines.txt' ? 'stacks of all goroutines' : name === 'threads.txt' ? 'stacks of all threads' : '';
// How long a capture took.
const took = c => { const s = Math.round((new Date(c.finishedAt) - new Date(c.createdAt)) / 1000); return s < 1 ? 'under a second' : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`; };
const marks = {Waiting: ['○', 'waits'], Running: ['●', 'runs'], Completed: ['✓', 'done'], Failed: ['✗', 'failed']};
function progressOf(c) {
  if (c.state !== 'Running') return '';
  if (c.stoppedAt) return '<div class="progress"><div class="muted">stopping…</div></div>';
  // The countdown runs in the browser from what the hub said was left.
  if (c.remainingSeconds == null) return '<div class="progress"><div class="muted">working…</div></div>';
  return `<div class="progress" data-ends="${Date.now() + c.remainingSeconds * 1000}" data-total="${c.durationSeconds}"><div class="track"><div class="bar"></div></div><div class="muted left"></div></div>`;
}
function countdown() {
  for (const el of document.querySelectorAll('.progress[data-ends]')) {
    const left = Math.max(0, Math.round((el.dataset.ends - Date.now()) / 1000)), total = Number(el.dataset.total) || 1;
    el.querySelector('.bar').style.width = Math.min(100, 100 * (1 - left / total)) + '%';
    el.querySelector('.left').textContent = left ? `about ${left} s left` : 'finishing: writing the files';
  }
}
setInterval(countdown, 1000);

// What was just created is highlighted for a few seconds, also when the list is drawn again meanwhile.
let fresh = {id: '', until: 0};
const freshClass = id => id === fresh.id && Date.now() < fresh.until ? ' fresh' : '';

// Which captures are opened: those in progress by themselves, any other by a click.
// What the user opened stays open over a visit to one of its files and the
// way back, for which the browser loads this page anew: it is kept with
// the session, as the token is.
const kept = name => { try { return new Map(JSON.parse(sessionStorage.getItem(name) || '[]')); } catch { return new Map(); } };
const keep = (name, map) => { try { sessionStorage.setItem(name, JSON.stringify([...map])); } catch { /* a session that keeps nothing forgets it */ } };
const toggled = kept('openCaptures');
// A capture of more pods than these lists them a line each, and a pod's
// files when it is opened: more of them with their files fill screen after
// screen. podsToggled says which pods the user opened or closed.
const podsOpen = 5, podsToggled = kept('openPods');
let captureFilter = 'all';
const inProgress = c => ['PendingApproval', 'Queued', 'Running'].includes(c.state);
// Where a request needs several approvals: how far it is, and whether this user has given theirs.
const approvalsOf = r => me.approvalsNeeded > 1 ? `${(r.approvals || []).length} of ${me.approvalsNeeded} approvals${(r.approvals || []).length ? ': ' + esc(r.approvals.join(', ')) : ''}` : '';
const approvedByMe = r => (r.approvals || []).includes(me.name);

// The hub lists captures a page at a time, the newest first; pages is how
// many of them the list shows.
let pages = 1;
const pageSize = 50;
// The requests of others that wait for this user's word. An administrator
// has them in the list of captures and of watches; for someone whom a
// cluster lets approve in a namespace they are shown here.
async function loadApprovals() {
  const waiting = me.admin ? {captures: [], watches: []} : await call('GET', '/api/approvals').catch(() => ({captures: [], watches: []}));
  const asks = [...waiting.captures.map(c => ({...c, path: 'captures', is: `capture ${String(c.number).padStart(4, '0')}`})), ...waiting.watches.map(w => ({...w, path: 'watches', is: `a watch (${told(w.when)})`}))];
  $('approvals').hidden = !asks.length;
  $('approvals').innerHTML = !asks.length ? '' : `<h3>Awaiting your approval</h3>` + asks.map(a => `<div class="ask">
    <span class="what"><b>${esc(a.requester)}</b> asks for ${esc(a.is)}: ${esc(list2((a.recordings || []).map(r => kindNames[r.kind] || r.kind)))} of ${esc(a.workload)} in ${esc(a.cluster)} / ${esc(a.namespace)}
      <div class="muted">${a.reason ? `“${esc(a.reason)}”` : 'No reason given.'}${approvalsOf(a) ? ' · ' + approvalsOf(a) : ''}</div></span>
    <span class="acts"><button class="primary" data-path="${a.path}" data-id="${a.id}" data-act="approve" title="${me.approvalsNeeded > 1 ? 'Give your approval. It starts with the last one it needs.' : 'Let it start'}">Approve</button>${a.path === 'captures' ? `<button data-path="captures" data-id="${a.id}" data-act="deny" title="Refuse the request. It will not start.">Deny</button>` : ''}</span></div>`).join('');
}
async function loadCaptures() {
  await loadApprovals();
  let all = [];
  for (let i = 0; i < pages; i++) {
    const page = await call('GET', '/api/captures' + (all.length ? '?before=' + encodeURIComponent(all.at(-1).createdAt) : ''));
    all = all.concat(page);
    if (page.length < pageSize) { pages = i + 1; break; }
  }
  $('olderLine').hidden = all.length < pages * pageSize;
  const words = $('captureFind').value.toLowerCase().split(/\s+/).filter(Boolean);
  const text = c => [String(c.number).padStart(4, '0'), c.cluster, c.namespace, c.workload, c.requester, c.reason, c.state, ...c.recordings.map(r => kindNames[r.kind] || r.kind), ...c.tasks.map(t => t.pod)].join(' ').toLowerCase();
  $('captureCount').textContent = all.filter(inProgress).length || '';
  const list = all.filter(c => (captureFilter === 'all' || (captureFilter === 'active') === inProgress(c)) && words.every(w => text(c).includes(w)));
  $('noCaptures').hidden = !!list.length;
  $('noCaptures').innerHTML = words.length && all.length ? 'No captures match.' : captureFilter === 'active' ? 'No captures in progress.' : captureFilter === 'done' ? 'No finished captures yet.'
    : 'No captures yet. <a href="#new">Start one</a>: pick a workload, choose what to record, and the files show up here.';
  // The list is written anew with every change: who works it with the keyboard stays where they were.
  // They stay on the same control of the same capture (a button by what it does, a link by where it leads), or,
  // when that capture has gone, at its place in the list.
  // A control is told by what it does, the pod it opens or where it leads.
  const controls = 'a[href], button', control = c => c.dataset.act || c.dataset.pod || c.getAttribute('href'), held = document.activeElement?.closest?.('#captures .capture');
  const focused = held && {id: held.dataset.capture, control: control(document.activeElement), place: [...$('captures').children].indexOf(held)};
  $('captures').innerHTML = list.map(c => {
    const open = toggled.has(c.id) ? toggled.get(c.id) : inProgress(c);
    // Each pod's recordings, in the order they were asked for, and under
    // each the files it made. A file of no recording that names its files
    // is one of the profile endpoint's.
    const asked = c.recordings.map(r => r.kind);
    const fileLine = a => {
      // A file with a viewer opens in the browser; every file downloads in its own format.
      const address = `/api/captures/${c.id}/artifacts/${a.name.split('/').map(encodeURIComponent).join('/')}`, name = a.name.split('/')[1];
      const open = a.viewer && a.size ? `<a class="open" href="/view?capture=${c.id}&file=${encodeURIComponent(a.name)}" title="Look at the file here">Open</a>` : '<span></span>';
      return `<div class="file${a.size ? '' : ' nothing'}"><span class="name" title="sha256 ${a.sha256}">${a.size ? `<a href="${a.viewer ? `/view?capture=${c.id}&file=${encodeURIComponent(a.name)}` : address}">${esc(name)}</a>` : esc(name)}</span><span class="is">${esc(a.size ? whatIs(name) : 'empty: nothing was recorded')}</span><span class="size"${a.stored ? ` title="${fileSize(a.size)} to download. The hub stores ${fileSize(a.stored)} of it: a core dump is as large as the memory its process mapped, and what the process never used is not stored."` : ''}>${fileSize(a.size)}</span>${open}<a href="${address}" title="A copy in the file's own format, for your tools">Download</a></div>`;
    };
    const folds = c.tasks.length > podsOpen;
    const pods = c.tasks.map(t => {
      const mine = c.artifacts.filter(a => a.name.startsWith(t.pod + '/'));
      // A file whose recording was not asked for, which should not be, is shown all the same.
      const from = a => { const kind = a.recording || (asked.includes('pprof') ? 'pprof' : ''); return asked.includes(kind) ? kind : ''; };
      const of = kind => mine.filter(a => from(a) === kind);
      const states = new Map((t.recordings || []).map(r => [r.kind, r]));
      const groups = asked.map(kind => {
        const r = states.get(kind) || {state: t.recordings?.length ? 'Waiting' : t.state === 'Failed' ? 'Failed' : 'Waiting'};
        const given = Object.entries(c.recordings.find(q => q.kind === kind)?.params || {}).filter(([k]) => k !== 'before').map(([k, v]) => v === 'true' ? k : `${k} ${v}`).join(' · ');
        return `<div class="rec rec-${esc(r.state)}"><div class="of"><span class="mark" title="${marks[r.state]?.[1] || ''}">${marks[r.state]?.[0] || ''}</span><b>${esc(kindNames[kind] || kind)}</b>${given ? `<span class="given">${esc(given)}</span>` : ''}${r.message ? `<span class="said">${esc(r.message)}</span>` : ''}</div>${of(kind).map(fileLine).join('')}</div>`;
      }).join('');
      const others = of('').map(fileLine).join('');
      const head = `<span>${esc(t.pod)}</span><span class="muted">on ${esc(t.node || 'no node')}${t.recordings?.length ? '' : ' · ' + esc(t.state)}</span>`;
      const body = `${groups}${others ? `<div class="rec"><div class="of"><b>Other files</b></div>${others}</div>` : ''}`
        + (t.message && !t.recordings?.some(r => r.message) ? `<div class="muted">${esc(t.message)}</div>` : '');
      if (!folds) return `<div class="podbox open"><div class="pod">${head}</div>${body}</div>`;
      // The line of a folded pod says how each recording went on it and what it left.
      const key = c.id + '/' + t.pod, shown = !!podsToggled.get(key);
      const went = asked.map(kind => { const state = states.get(kind)?.state || (t.state === 'Failed' ? 'Failed' : 'Waiting'); return `<span class="rec-${esc(state)}"><span class="mark" title="${marks[state]?.[1] || ''}">${marks[state]?.[0] || ''}</span>${esc(kindNames[kind] || kind)}</span>`; }).join('');
      return `<div class="podbox folds${shown ? ' open' : ''}"><button class="pod" data-pod="${esc(key)}" aria-expanded="${shown}">${head}<span class="went">${went}</span><span class="muted">${mine.length ? `${plural(mine.length, 'file')}, ${fileSize(mine.reduce((n, a) => n + a.size, 0))}` : 'no files'}</span></button><div class="podbody">${body}</div></div>`;
    }).join('') || '<div class="muted">No pods were recorded.</div>';
    const facts = [c.reason && `“${esc(c.reason)}”`, c.durationSeconds ? `time frame ${c.durationSeconds} s` : '', c.watch ? `recorded by <a href="#watches" title="The watches that still wait">a watch</a>${c.on ? ' (' + esc(conditions[c.on] || c.on) + ')' : ''}` : '',
      c.approver ? (c.approver === c.requester ? '' : 'approved by ' + esc(c.approver)) : c.sensitive ? (c.state === 'PendingApproval' && approvalsOf(c) || 'needs approval') : '', c.finishedAt && !inProgress(c) && new Date(c.finishedAt) > new Date(c.createdAt) ? `took ${took(c)}` : '',
      c.artifacts.length ? `${plural(c.artifacts.length, 'file')}, ${fileSize(c.artifacts.reduce((n, a) => n + a.size, 0))}, kept until ${new Date(c.expiresAt).toLocaleDateString()}` : ''].filter(Boolean).join(' · ');
    // Its requester and administrators may change a capture; others see one that is shared with them.
    const mine = me.admin || c.requester === me.name;
    const sharing = c.shared ? `Shared with everyone who may capture in ${esc(c.namespace)}.` : mine ? `Only you${me.admin && c.requester !== me.name ? ', ' + esc(c.requester) : ''} and administrators see this capture.` : '';
    const share = !mine ? '' : `<button data-act="share" data-id="${c.id}" data-shared="${c.shared ? '' : '1'}" title="${c.shared ? 'Make it visible to you and administrators only again' : `Let everyone who may capture in ${esc(c.namespace)} look at this capture and download its files. They cannot change or delete it.`}">${c.shared ? 'Stop sharing' : 'Share with the namespace'}</button>`;
    const button = (act, text, title, primary) => `<button data-act="${act}" data-id="${c.id}" title="${title}"${primary ? ' class="primary"' : ''}>${text}</button>`;
    const actions = !mine ? '' : c.state === 'PendingApproval' ? (me.admin ? (approvedByMe(c) ? '' : button('approve', 'Approve', me.approvalsNeeded > 1 ? 'Give your approval. It starts with the last one it needs.' : 'Let it start', true)) + button('deny', 'Deny', 'Refuse the request. It will not start.') : '') + button('cancel', 'Withdraw', 'Withdraw the request')
      : c.state === 'Running' && c.stoppedAt ? button('delete', 'Delete', 'Stop it and delete what it has recorded')
      : c.state === 'Running' ? button('stop', 'Stop and keep', 'Stop recording now and keep the files so far', true) + button('delete', 'Delete', 'Stop it and delete what it has recorded')
      : button('delete', 'Delete', 'Delete the capture and its files');
    const state = {PendingApproval: 'Awaiting approval'}[c.state] || c.state;
    const count = c.artifacts.length ? ` · ${plural(c.artifacts.length, 'file')}, ${fileSize(c.artifacts.reduce((n, a) => n + a.size, 0))}` : '';
    // What tells this capture from the others like it: why it was made.
    const why = c.reason || (c.watch ? 'recorded by a watch' : '');
    return `<div class="capture${open ? ' open' : ''}${freshClass(c.id)}" data-capture="${c.id}">
      <div class="line">
        <span class="number${c.artifacts.length ? ' filed' : ''}" title="Capture ${c.number}${c.artifacts.length ? '' : ': no files yet'}">${String(c.number).padStart(4, '0')}</span>
        <span><span class="pill state ${c.state}">${state}</span>${c.state === 'Running' ? progressOf(c) : `<div class="muted${c.message && !inProgress(c) ? ' error' : ''}" title="${esc(c.message || '')}">${inProgress(c) ? '' : esc(c.message) || count.slice(3)}</div>`}</span>
        <span class="what" title="${esc(c.recordings.map(r => kindNames[r.kind] || r.kind).join(', '))}${why ? '\n' + esc(why) : ''}">${esc(list2(c.recordings.map(r => kindNames[r.kind] || r.kind)))}${why ? `<div class="muted why">${esc(why)}</div>` : ''}</span>
        <span class="where" title="${esc(c.cluster)} / ${esc(c.namespace)} / ${esc(c.workload)}">${esc(c.workload)}<div class="muted">${esc(c.cluster)} / ${esc(c.namespace)}</div></span>
        <span class="when muted">${new Date(c.createdAt).toLocaleString()}<div>${esc(c.requester)}</div></span>
        <span class="acts">${actions}</span><button class="chev" aria-expanded="${open}" aria-label="Details and files of capture ${c.number}"></button>
      </div>
      <div class="more">
        <div class="facts muted">${facts}</div>
        ${sharing || share ? `<div class="sharing muted">${sharing} ${share}</div>` : ''}
        ${pods}
      </div></div>`;
  }).join('');
  if (sought) {
    const card = document.querySelector(`.capture[data-capture="${CSS.escape(sought)}"]`);
    if (card) {
      card.scrollIntoView({block: 'center'}); card.classList.add('fresh'); sought = '';
    } else if (!$('olderLine').hidden) {
      pages++;
      return loadCaptures(); // it is further back
    } else {
      sought = '';
      $('capturesProblem').textContent = 'This capture is not there any more, or not yours to see.';
    }
  }
  if (focused) {
    const card = document.querySelector(`.capture[data-capture="${focused.id}"]`), near = $('captures').children[Math.min(focused.place, $('captures').children.length - 1)];
    (card ? [...card.querySelectorAll(controls)].find(c => control(c) === focused.control) || card.querySelector('.chev') : near?.querySelector('.chev') || $('captureFind')).focus();
  }
  countdown();
}
const list2 = words => words.length > 3 ? `${words.slice(0, 3).join(', ')} +${words.length - 3}` : words.join(', ');

$('loginForm').onsubmit = guard(async () => { sessionStorage.setItem('token', $('token').value.trim()); await start(); if (!me) throw new Error('This token was not accepted.'); });
$('signout').onclick = async () => {
  sessionStorage.clear(); document.cookie = 'asservat_token=; path=/; max-age=0';
  await fetch('/auth/logout', {method: 'POST'}).catch(() => {}); // ends a single sign-on session, if any
  location.reload();
};
$('cluster').onchange = guard(loadNamespaces, 'whereProblem');
$('namespace').onchange = guard(loadWorkloads, 'whereProblem');
$('workload').onchange = guard(workloadChanged, 'whereProblem');
$('captureForm').onchange = guard(async e => { showParams(); if (['kind', 'when'].includes(e.target.name)) await Promise.all([loadProcesses(), loadProfiles()]); }, 'formProblem');
$('profilePath').oninput = showParams;
$('sample').onclick = guard(async () => {
  if (!$('workload').value) return;
  const of = target(), seconds = $('sampleSeconds').value;
  $('sample').disabled = true;
  $('sampleState').textContent = `Sampling traffic for ${seconds} seconds…`;
  try {
    const sample = await call('POST', `${namespacePath()}/traffic?${workloadQuery()}&seconds=${seconds}`);
    if (of === target()) showFlows(sample);
  } catch (err) {
    showFlows(null);
    throw err;
  } finally {
    $('sample').disabled = false;
    $('sample').textContent = 'Look again';
  }
}, 'sampleProblem');
$('flows').onclick = e => {
  const box = e.target.closest('tr')?.querySelector('input');
  if (!box) return;
  if (e.target !== box) box.checked = !box.checked;
  filterChanged();
};
$('filter').oninput = () => filterChanged(true);
$('captureForm').onsubmit = guard(async () => {
  const crash = picked('when') === 'crash', watching = picked('when') !== 'now';
  // What is missing is said at its own step, not after a round trip.
  for (const n of [1, 2, 3]) {
    const problem = stepProblem(n);
    if (problem) return problemAt(...problem);
  }
  const profile = kinds().includes('pprof') ? profileParams() : {};
  // Each chosen kind becomes a recording with the parameters of its section.
  const recordings = kinds().map(kind => {
    const params = {};
    for (const el of document.querySelectorAll(`[data-of="${kind}"]`)) if (!el.closest('[hidden]') && el.value) params[el.dataset.param] = el.value;
    if (kind === 'pcap' && picked('payload')) params.payload = 'true';
    if (kind === 'strace' && picked('strings')) params.strings = 'true';
    if (kind === 'pprof') Object.assign(params, profile);
    if (watching && ['pcap', 'cpu', 'memory', 'strace'].includes(kind)) params.before = String($({pcap: 'beforePcap', cpu: 'beforeCpu', memory: 'beforeMemory', strace: 'beforeStrace'}[kind]).checked);
    if (['coredump', 'strace'].includes(kind) && wantsProcess() && !(kind === 'coredump' && crash) && $('process').value.startsWith('{')) Object.assign(params, JSON.parse($('process').value));
    return {kind, params};
  });
  const request = {cluster: $('cluster').value, namespace: $('namespace').value, workload: $('workload').value, recordings,
    durationSeconds: $('frameBlock').hidden ? 0 : Number($('duration').value || 0), reason: $('reason').value};
  const created = watching ? await call('POST', '/api/watches', {...request, when: condition(), count: Number($('count').value || 1), ...($('beforeSeconds').value > 0 && !$('beforeFields').hidden ? {beforeSeconds: Math.round($('beforeSeconds').value)} : {})}) : await call('POST', '/api/captures', request);
  await Promise.all([loadCaptures(), loadWatches()]);
  const waits = created.sensitive && !created.approver && created.state !== 'Queued';
  $('done').textContent = watching ? (waits ? 'The watch is awaiting approval.' : `Watching. The capture will appear under Captures ${told(condition())}.`)
    : waits ? 'Requested. It starts once an administrator approves it.' : 'Started. Follow its progress in the first row below.';
  // Show where it went: the new capture, opened, in its list.
  if (!watching) { toggled.set(created.id, true); keep('openCaptures', toggled); }
  fresh = {id: created.id, until: Date.now() + 4000};
  captureFilter = 'all';
  for (const b of $('states').children) b.classList.toggle('on', b.dataset.filter === 'all');
  await Promise.all([loadCaptures(), loadWatches()]);
  location.hash = watching ? '#watches' : '#captures';
  showStep(1);
  document.querySelector(watching ? `tr[data-watch="${created.id}"]` : `.capture[data-capture="${created.id}"]`)?.scrollIntoView({block: 'nearest', behavior: 'smooth'});
}, 'formProblem');
function problemAt(id, message) {
  showStep(Number($(id).closest('[data-step]').dataset.step));
  $(id).textContent = message;
  $(id).scrollIntoView({block: 'center', behavior: 'smooth'});
}

// The form is filled one step at a time. A step without anything to choose is passed over.
let step = 1;
const stepNeeded = n => n !== 3 || $('nothing').hidden;
function showStep(n) {
  step = n;
  for (const f of document.querySelectorAll('[data-step]')) f.hidden = Number(f.dataset.step) !== step;
  for (const li of $('steps').children) {
    const k = Number(li.dataset.go);
    li.className = k === step ? 'on' : !stepNeeded(k) ? 'skip' : k < step ? 'done' : '';
    li.title = li.className === 'skip' ? 'Nothing to set for what you chose to record. Choose a recording that has settings, such as network traffic, and this step opens.' : '';
  }
  $('back').hidden = step === 1;
  $('next').hidden = step === 4;
  $('submit').hidden = step !== 4;
  summarize();
}
// What the step needs before the next one; the message appears at the step.
function stepProblem(n) {
  if (n === 1 && !$('nowhere').hidden) return ['whereProblem', 'There is no namespace here that you may capture in.'];
  if (n === 1 && !$('workload').value) return ['whereProblem', 'Choose a cluster, a namespace and a workload.'];
  if (n === 2 && !kinds().length) return ['kindProblem', 'Choose at least one recording.'];
  if (n === 3 && kinds().includes('pprof')) try { profileParams(); } catch (err) { return ['profileProblem', err.message]; }
  return null;
}
function go(to) {
  // Going forward checks every step on the way.
  for (let n = step; n < to; n++) {
    const problem = stepProblem(n);
    if (problem) return problemAt(...problem);
  }
  while (!stepNeeded(to)) to += to > step ? 1 : -1;
  showStep(to);
  window.scrollTo({top: 0, behavior: 'smooth'});
}
$('next').onclick = () => go(step + 1);
$('back').onclick = () => go(step - 1);
$('steps').onclick = e => { const li = e.target.closest('li'); if (li && stepNeeded(Number(li.dataset.go))) go(Number(li.dataset.go)); };
// The choices so far, in one line above the steps.
function summarize() {
  const where = $('workload').value ? `${$('workload').value} in ${$('cluster').value} / ${$('namespace').value}` : '';
  const what = kinds().length ? list(kinds().map(k => kindNames[k])) : '';
  const when = step === 4 ? (picked('when') === 'time' ? 'at a time' : conditions[picked('when')] || 'now') : '';
  $('summary').textContent = [where, what, when].filter(Boolean).join('  ·  ');
}
$('watches').onclick = guard(async e => {
  if (!e.target.dataset.id) return;
  if (e.target.dataset.act === 'approve') await call('POST', `/api/watches/${e.target.dataset.id}/approve`);
  else if (e.target.dataset.act === 'record') await call('POST', `/api/watches/${e.target.dataset.id}/record`);
  else await call('DELETE', `/api/watches/${e.target.dataset.id}`);
  await loadWatches();
}, 'watchesProblem');
$('captureFind').oninput = guard(loadCaptures, 'capturesProblem');
$('auditOlder').onclick = guard(() => loadAudit(false), 'auditProblem');
$('older').onclick = guard(async () => { pages++; await loadCaptures(); }, 'capturesProblem');
$('states').onclick = guard(async e => {
  if (!e.target.dataset.filter) return;
  captureFilter = e.target.dataset.filter;
  for (const b of $('states').children) b.classList.toggle('on', b === e.target);
  await loadCaptures();
}, 'capturesProblem');
$('approvals').onclick = guard(async e => {
  const {path, id, act} = e.target.dataset;
  if (!act) return;
  await call('POST', `/api/${path}/${id}/${act}`);
  await loadCaptures();
}, 'capturesProblem');
$('captures').onclick = guard(async e => {
  const {act, id} = e.target.dataset, card = e.target.closest('.capture');
  if (!act) {
    // A click on the line of a folded pod opens or closes its files.
    const pod = e.target.closest('button.pod');
    if (pod) {
      podsToggled.set(pod.dataset.pod, pod.parentElement.classList.toggle('open'));
      keep('openPods', podsToggled);
      pod.setAttribute('aria-expanded', pod.parentElement.classList.contains('open'));
      return;
    }
    // A click on the line opens or closes the capture; links and text selection in the details are left alone.
    if (card && e.target.closest('.line')) {
      toggled.set(card.dataset.capture, card.classList.toggle('open'));
      keep('openCaptures', toggled);
      card.querySelector('.chev').setAttribute('aria-expanded', card.classList.contains('open'));
    }
    return;
  }
  const running = card.querySelector('.state.Running');
  if (act === 'delete' && running && !confirm('Abandon this capture and delete what it has recorded? "Stop and keep" ends it and keeps the files.')) return;
  // Files that are deleted are gone for everyone.
  const number = card.querySelector('.number'), files = card.querySelectorAll('.file').length;
  if (act === 'delete' && !running && files && !confirm(`Delete capture ${number.textContent} and its ${files === 1 ? 'file' : files + ' files'}? This cannot be undone.`)) return;
  if (act === 'share') await call('POST', `/api/captures/${id}/share`, {shared: !!e.target.dataset.shared});
  else await call(act === 'delete' ? 'DELETE' : 'POST', `/api/captures/${id}` + (act === 'delete' ? '' : '/' + act));
  await loadCaptures();
}, 'capturesProblem');
showParams();
$('ssoButton').onclick = () => { location.href = '/auth/login'; };
start();
