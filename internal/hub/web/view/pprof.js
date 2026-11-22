// A profile is shown by pprof itself: the hub holds the pages of pprof's web
// interface for the open file, and this page frames them.
import {openView, show} from './common.js';

export default function (root) {
  root.innerHTML = '<iframe id="pprof" title="pprof"></iframe>';
  openView(id => { root.firstChild.src = `/api/views/${id}/pages/`; show(); });
}
