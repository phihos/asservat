// A Go execution trace is shown by Go's own trace tool, which the hub runs
// for the open file; this page frames its pages.
import {openView, show} from './common.js';

export default function (root) {
  root.innerHTML = '<iframe id="gotrace" title="Go trace tool"></iframe>';
  openView(id => { root.firstChild.src = `/api/views/${id}/pages/`; show(); });
}
