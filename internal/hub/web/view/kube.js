// The viewer for pod state follows the detail panels of Lens and the
// Kubernetes dashboard: a pod's properties, conditions, containers and
// volumes, or the table of its events; and the object itself as a tree that
// folds, like a browser's JSON viewer.
import {$, esc, file, loadText, moment, show} from './common.js';

const markup = `
  <div class="tabs"><button data-tab="overview" class="on">Overview</button><button data-tab="json">JSON</button></div>
  <div id="overview" class="tab"></div>
  <div id="json" class="tab" hidden>
    <div class="narrow"><input id="filter" type="search" placeholder="Filter JSON" autocomplete="off" spellcheck="false"><button id="expand">Expand all</button><button id="collapse">Collapse all</button></div>
    <div id="tree"></div>
  </div>
`;
const when = t => t ? esc(String(t).replace('T', ' ').replace('Z', ' UTC')) : '';
const chips = o => Object.entries(o || {}).map(([k, v]) => `<span class="chip" title="${esc(k)}=${esc(v)}">${esc(k)}=${esc(v)}</span>`).join('') || '<span class="muted">none</span>';
const rows = list => `<table class="props">${list.filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join('')}</table>`;
const badge = (text, kind) => `<span class="badge ${kind}">${esc(text)}</span>`;

// What Lens shows as a container's state.
function stateOf(state) {
  if (!state) return ['Unknown', 'warn', ''];
  if (state.running) return ['Running', 'ok', `since ${when(state.running.startedAt)}`];
  if (state.waiting) return [state.waiting.reason || 'Waiting', 'warn', esc(state.waiting.message || '')];
  const t = state.terminated;
  return [t.reason || 'Terminated', t.exitCode ? 'bad' : 'done', `exit code ${t.exitCode}${t.signal ? `, signal ${t.signal}` : ''} · ${when(t.startedAt)} to ${when(t.finishedAt)}${t.message ? ' · ' + esc(t.message) : ''}`];
}
// The pod's status as "kubectl get pods" words it: the reason of a container that is not running wins over the phase.
function podStatus(pod) {
  const statuses = [...(pod.status?.initContainerStatuses || []), ...(pod.status?.containerStatuses || [])];
  if (pod.metadata?.deletionTimestamp) return ['Terminating', 'warn'];
  for (const s of statuses) {
    if (s.state?.waiting?.reason) return [s.state.waiting.reason, 'bad'];
    if (s.state?.terminated && s.state.terminated.exitCode) return [s.state.terminated.reason || 'Error', 'bad'];
  }
  const phase = pod.status?.phase || 'Unknown';
  return [phase, {Running: 'ok', Succeeded: 'done', Pending: 'warn'}[phase] || 'bad'];
}
const quantity = r => Object.entries(r || {}).map(([k, v]) => `${esc(k)} ${esc(v)}`).join(', ');
const source = e => e.value !== undefined ? esc(e.value) : e.valueFrom?.secretKeyRef ? `secret ${esc(e.valueFrom.secretKeyRef.name)}/${esc(e.valueFrom.secretKeyRef.key)}`
  : e.valueFrom?.configMapKeyRef ? `config map ${esc(e.valueFrom.configMapKeyRef.name)}/${esc(e.valueFrom.configMapKeyRef.key)}`
  : e.valueFrom?.fieldRef ? `field ${esc(e.valueFrom.fieldRef.fieldPath)}` : e.valueFrom?.resourceFieldRef ? `resource ${esc(e.valueFrom.resourceFieldRef.resource)}` : '';
const volumeKind = v => Object.keys(v).find(k => k !== 'name') || '';

function container(c, status, init) {
  const [state, kind, detail] = stateOf(status?.state), last = status?.lastState && Object.keys(status.lastState).length ? stateOf(status.lastState) : null;
  return `<div class="container"><h3>${esc(c.name)} ${badge(state, kind)}${init ? ' <span class="muted">init container</span>' : ''}${status && !init ? ` <span class="muted">${status.ready ? 'ready' : 'not ready'} · ${status.restartCount} restart${status.restartCount === 1 ? '' : 's'}</span>` : ''}</h3>` + rows([
    ['State', detail],
    ['Last state', last ? `${badge(last[0], last[1])} ${last[2]}` : ''],
    ['Image', esc(c.image)],
    ['Image ID', status?.imageID ? esc(status.imageID) : ''],
    ['Command', c.command ? `<code>${esc(c.command.join(' '))}</code>` : ''],
    ['Arguments', c.args ? `<code>${esc(c.args.join(' '))}</code>` : ''],
    ['Ports', (c.ports || []).map(p => `${p.name ? esc(p.name) + ': ' : ''}${p.containerPort}/${esc(p.protocol || 'TCP')}`).join(', ')],
    ['Requests', quantity(c.resources?.requests)],
    ['Limits', quantity(c.resources?.limits)],
    ['Environment', (c.env || []).map(e => `<div><code>${esc(e.name)}</code> ${source(e)}</div>`).join('')],
    ['Mounts', (c.volumeMounts || []).map(m => `<div><code>${esc(m.mountPath)}</code> from ${esc(m.name)}${m.readOnly ? ' (read-only)' : ''}</div>`).join('')],
    ['Liveness', c.livenessProbe ? probe(c.livenessProbe) : ''],
    ['Readiness', c.readinessProbe ? probe(c.readinessProbe) : ''],
    ['Startup', c.startupProbe ? probe(c.startupProbe) : ''],
  ]) + '</div>';
}
const probe = p => esc((p.httpGet ? `http-get ${p.httpGet.scheme || 'HTTP'} :${p.httpGet.port}${p.httpGet.path || ''}` : p.tcpSocket ? `tcp-socket :${p.tcpSocket.port}` : p.exec ? `exec ${(p.exec.command || []).join(' ')}` : p.grpc ? `grpc :${p.grpc.port}` : '')
  + ` · delay ${p.initialDelaySeconds || 0}s, period ${p.periodSeconds || 10}s, timeout ${p.timeoutSeconds || 1}s, failure threshold ${p.failureThreshold || 3}`);

function podOverview(pod) {
  const [status, kind] = podStatus(pod), meta = pod.metadata || {}, spec = pod.spec || {}, st = pod.status || {};
  const statusOf = (list, name) => (list || []).find(s => s.name === name);
  return `<h2>${esc(meta.name)} ${badge(status, kind)}</h2>` + rows([
    ['Namespace', esc(meta.namespace)],
    ['Created', when(meta.creationTimestamp)],
    ['Node', spec.nodeName ? esc(spec.nodeName) + (st.hostIP ? ` <span class="muted">${esc(st.hostIP)}</span>` : '') : ''],
    ['Pod IP', (st.podIPs || []).map(i => esc(i.ip)).join(', ') || esc(st.podIP || '')],
    ['Controlled by', (meta.ownerReferences || []).map(o => `${esc(o.kind)} ${esc(o.name)}`).join(', ')],
    ['Service account', esc(spec.serviceAccountName || '')],
    ['QoS class', esc(st.qosClass || '')],
    ['Priority class', esc(spec.priorityClassName || '')],
    ['Message', st.message ? esc(`${st.reason || ''} ${st.message}`.trim()) : ''],
    ['Labels', chips(meta.labels)],
    ['Annotations', chips(meta.annotations)],
  ]) + `<h2>Conditions</h2><table class="grid"><thead><tr><th>Type</th><th>Status</th><th>Last transition</th><th>Reason</th><th>Message</th></tr></thead><tbody>${
    (st.conditions || []).map(c => `<tr><td>${esc(c.type)}</td><td>${badge(c.status, c.status === 'True' ? 'ok' : 'bad')}</td><td>${when(c.lastTransitionTime)}</td><td>${esc(c.reason || '')}</td><td>${esc(c.message || '')}</td></tr>`).join('')}</tbody></table>`
    + `<h2>Containers</h2>` + (spec.initContainers || []).map(c => container(c, statusOf(st.initContainerStatuses, c.name), true)).join('') + (spec.containers || []).map(c => container(c, statusOf(st.containerStatuses, c.name))).join('')
    + `<h2>Volumes</h2><table class="grid"><thead><tr><th>Name</th><th>Kind</th><th>Source</th></tr></thead><tbody>${
      (spec.volumes || []).map(v => { const k = volumeKind(v), src = v[k] || {}; return `<tr><td>${esc(v.name)}</td><td>${esc(k)}</td><td>${esc(src.secretName || src.claimName || src.name || src.path || src.medium || '')}</td></tr>`; }).join('')}</tbody></table>`;
}
function eventsOverview(events) {
  if (!events.length) return '<p class="muted">The pod had no events when it was recorded. Kubernetes keeps events for about an hour.</p>';
  const last = e => e.lastTimestamp || e.eventTime || e.firstTimestamp || '';
  return `<table class="grid events"><thead><tr><th>Type</th><th>Reason</th><th>Message</th><th>From</th><th>Count</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${
    [...events].sort((a, b) => last(b).localeCompare(last(a))).map(e => `<tr class="${e.type === 'Warning' ? 'warning' : ''}" data-at="${esc(last(e))}" title="Select the event to open the logs, packets or calls of its moment"><td>${badge(e.type || 'Normal', e.type === 'Warning' ? 'warn' : 'done')}</td><td>${esc(e.reason || '')}</td><td>${esc(e.message || '')}</td><td>${esc(e.source?.component || e.reportingComponent || '')}</td><td>${e.count || 1}</td><td>${when(e.firstTimestamp || e.eventTime)}</td><td>${when(last(e))}</td></tr>`).join('')}</tbody></table>`;
}

// The JSON tree. With a filter, only the values whose key or text matches
// remain, under their parents.
function tree(value, key, words, open) {
  const label = key === null ? '' : `<span class="k">${esc(key)}</span>: `;
  if (value === null || typeof value !== 'object') {
    const text = JSON.stringify(value);
    if (words && !text.toLowerCase().includes(words) && !String(key).toLowerCase().includes(words)) return '';
    return `<div class="leaf">${label}<span class="${value === null ? 'null' : typeof value}">${esc(text)}</span></div>`;
  }
  const array = Array.isArray(value), entries = array ? value.map((v, i) => [i, v]) : Object.entries(value);
  const keyMatches = words && key !== null && String(key).toLowerCase().includes(words);
  const inner = entries.map(([k, v]) => tree(v, k, keyMatches ? '' : words, open)).join('');
  if (words && !inner && !keyMatches) return '';
  return `<details${open || words ? ' open' : ''}><summary>${label}<span class="muted">${array ? `[${entries.length}]` : `{${entries.length}}`}</span></summary>${inner}</details>`;
}

export default async function (root) {
  const {text} = await loadText();
  const value = JSON.parse(text), events = file.endsWith('/events.json');
  root.innerHTML = markup;
  $('overview').innerHTML = `<div class="page">${events ? eventsOverview(value || []) : podOverview(value)}</div>`;
  const draw = open => { $('tree').innerHTML = tree(value, null, $('filter').value.trim().toLowerCase(), open) || '<p class="muted">Nothing matches.</p>'; if (!open) $('tree').querySelector('details')?.setAttribute('open', ''); };
  root.querySelector('.tabs').onclick = e => {
    const name = e.target.dataset.tab;
    if (!name) return;
    for (const b of root.querySelectorAll('[data-tab]')) b.classList.toggle('on', b === e.target);
    $('overview').hidden = name !== 'overview'; $('json').hidden = name !== 'json';
  };
  // An event's moment leads to what the pod's other files recorded then.
  $('overview').onclick = e => {
    const row = e.target.closest('tr[data-at]');
    if (!row) return;
    for (const r of $('overview').querySelectorAll('tr.selected')) r.classList.remove('selected');
    row.classList.add('selected');
    moment(Date.parse(row.dataset.at) / 1000);
  };
  $('filter').oninput = () => draw(false);
  $('expand').onclick = () => draw(true);
  $('collapse').onclick = () => { $('filter').value = ''; draw(false); };
  draw(false);
  show();
}
