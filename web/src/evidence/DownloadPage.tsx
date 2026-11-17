import { useEffect, useRef, useState } from 'react';
import type { Session } from '../auth/session';
import { operations, operationMessage, type Download, type Operations } from './http';

// The browser_url of a download_artifact status: it starts the same session
// in this signed-in browser. Another principal gets the ordinary not-found result.
const assign = (path: string) => window.location.assign(path);

export function DownloadPage({ session, scope, downloadID, client = operations, start = assign }: { session: Session; scope: AbortSignal; downloadID: string; client?: Operations; start?: (path: string) => void }) {
  const [download, setDownload] = useState<Download>();
  const [message, setMessage] = useState<string>();
  // The latest start callback, outside the effect's dependencies: a new
  // callback must not restart the status wait or repeat the download.
  const startRef = useRef(start);
  startRef.current = start;
  useEffect(() => {
    let current = true;
    const request = new AbortController();
    const abort = () => request.abort();
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort();
    // A Preparing session is followed with after_revision: the server waits
    // for the next state instead of the page polling.
    void (async () => {
      let revision: number | undefined;
      try {
        for (;;) {
          const result = await client.call('download_artifact', { action: 'status', download_id: downloadID, ...(revision ? { after_revision: revision } : {}) }, session.csrf_token, request.signal);
          if (!current) return;
          if (result.status === 'error') { setMessage(result.data.message); return; }
          const data = result.data as Download;
          if (result.status !== 'ok' || data.download_id !== downloadID) { setMessage('This download is not available.'); return; }
          if (data.state === 'Preparing') { setDownload(data); revision = data.revision; continue; }
          if (data.state !== 'Ready' || data.content_path !== `/api/v1/downloads/${downloadID}/content`) { setDownload(undefined); setMessage(`This download ended: ${data.state}. Start a new download from the evidence page.`); return; }
          setDownload(data); startRef.current(data.content_path); return;
        }
      } catch (error) { if (current) setMessage(operationMessage(error)); }
    })();
    return () => { current = false; scope.removeEventListener('abort', abort); abort(); };
  }, [client, downloadID, scope, session.csrf_token]);
  return <div className="capture-workspace evidence-workspace">
    <div className="page-intro"><h1>Download</h1></div>
    {message && <p role="alert" className="notice">{message}</p>}
    {!message && (!download || download.state === 'Preparing') && <p role="status">{download ? 'Asservat is verifying the native file…' : 'Checking the download…'}</p>}
    {download?.state === 'Ready' && <>
      <dl className="facts"><dt>Native file</dt><dd>{download.filename}</dd><dt>Size</dt><dd>{new Intl.NumberFormat().format(download.size_bytes!)} bytes</dd><dt>SHA-256</dt><dd className="identifier">{download.sha256}</dd></dl>
      <a className="button" href={download.content_path} download={download.filename}>Download native file</a>
    </>}
    <p className="notice">Downloaded copies are outside Asservat's automatic deletion. Follow your organization's handling and deletion policy.</p>
  </div>;
}
