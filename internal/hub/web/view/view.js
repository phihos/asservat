// The viewer page: it finds the file and hands it to its viewer. A file of
// its own, so that the page can tell the browser to run no script from its markup.
import {$, esc, capture, file, address, headers, notice, onMoment} from '/view/common.js';

$('name').textContent = file.split('/').pop();
$('download').href = address;
document.title = file.split('/').pop() + ' – Asservat';

async function open() {
  if (!capture || !file) return notice('No file was specified.');
  const res = await fetch(`/api/captures/${capture}`, {headers}).catch(() => null);
  if (!res) return notice('Cannot reach the hub.', true);
  if (res.status === 401) return notice('Please sign in to the console first.');
  if (!res.ok) return notice('This capture no longer exists.');
  const c = await res.json(), artifact = c.artifacts.find(a => a.name === file);
  $('number').textContent = String(c.number).padStart(4, '0'); $('number').title = `Go to capture ${c.number}`; $('number').href = `/#capture=${encodeURIComponent(c.id)}`; $('number').hidden = false;
  document.title = `${$('number').textContent} ${$('name').textContent} – Asservat`;
  $('origin').textContent = `pod ${file.split('/')[0]} · ${c.workload} in ${c.namespace} on ${c.cluster}`;
  if (!artifact) return notice('This file no longer exists.');
  if (!artifact.viewer) return notice('This file has no viewer. Download it instead.');
  otherFiles(c);
  sameMoment(c);
  const style = document.createElement('link');
  style.rel = 'stylesheet'; style.href = `/view/${artifact.viewer}.css`;
  document.head.append(style);
  const viewer = await import(`/view/${artifact.viewer}.js`);
  await viewer.default($('root'), {capture: c, artifact});
}
// The file's name becomes the choice among the capture's files that have a
// viewer, so that the way to another one does not lead back over the list.
// A core's description opens with its core and is not listed.
function otherFiles(c) {
  const shown = c.artifacts.filter(a => a.viewer && !a.name.endsWith('.analysis.json'));
  if (shown.length < 2) return;
  const pods = new Set(shown.map(a => a.name.split('/')[0]));
  $('files').innerHTML = shown.map(a => {
    const [pod, name] = a.name.split('/');
    return `<option value="${esc(a.name)}"${a.name === file ? ' selected' : ''}>${esc(name)}${pods.size > 1 ? ' · ' + esc(pod) : ''}</option>`;
  }).join('');
  $('files').onchange = () => { location.href = `/view?capture=${capture}&file=${encodeURIComponent($('files').value)}`; };
  $('name').hidden = true; $('files').hidden = false;
}
// The capture's other files that know when things happened, this pod's
// first. They are offered once the viewer tells the moment of a selection.
function sameMoment(c) {
  const pod = file.split('/')[0];
  const timed = c.artifacts.filter(a => ['log', 'strace', 'pcap'].includes(a.viewer) && a.name !== file)
    .sort((a, b) => (b.name.startsWith(pod + '/') - a.name.startsWith(pod + '/')) || a.name.localeCompare(b.name));
  let at = null;
  $('moment').innerHTML = '<option value="">Jump to the same moment in …</option>' + timed.map(a => {
    const [where, name] = a.name.split('/');
    return `<option value="${esc(a.name)}">${esc(name)}${where === pod ? '' : ' of ' + esc(where)}</option>`;
  }).join('');
  onMoment(seconds => { at = seconds; $('moment').hidden = seconds === null || !timed.length; });
  $('moment').onchange = () => {
    if ($('moment').value) location.href = `/view?capture=${capture}&file=${encodeURIComponent($('moment').value)}#at=${at}`;
  };
}
$('copy').onclick = async () => {
  // Without the clipboard, the address bar holds the same link.
  try { await navigator.clipboard.writeText(location.href); $('copy').textContent = 'Copied'; } catch { $('copy').textContent = 'Copy it from the address bar'; }
};
open().catch(err => notice(err.message, true));
