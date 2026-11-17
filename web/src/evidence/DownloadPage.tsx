import { useEffect, useState } from 'react';
import type { Session } from '../auth/session';
import { operations, operationMessage, type Download, type Operations } from './http';

// The browser_url of a download_artifact status: it starts the same session
// in this signed-in browser. Another principal gets the ordinary not-found result.
export function DownloadPage({ session, scope, downloadID, client = operations, start = (path: string) => window.location.assign(path) }: { session: Session; scope: AbortSignal; downloadID: string; client?: Operations; start?: (path: string) => void }) {
  const [download, setDownload] = useState<Download>();
  const [message, setMessage] = useState<string>();
  useEffect(() => {
    let current = true;
    client.call('download_artifact', { action: 'status', download_id: downloadID }, session.csrf_token, scope).then(result => {
      if (!current) return;
      if (result.status === 'error') { setMessage(result.data.message); return; }
      const data = result.data as Download;
      if (result.status !== 'ok' || data.download_id !== downloadID || data.state !== 'Ready' || data.content_path !== `/api/v1/downloads/${downloadID}/content`) { setMessage('This download is not ready.'); return; }
      setDownload(data); start(data.content_path);
    }, error => { if (current) setMessage(operationMessage(error)); });
    return () => { current = false; };
  }, [client, downloadID, scope, session.csrf_token, start]);
  return <div className="capture-workspace evidence-workspace">
    <div className="page-intro"><h1>Download</h1></div>
    {message && <p role="alert" className="notice">{message}</p>}
    {!download && !message && <p role="status">Checking the download…</p>}
    {download && <>
      <dl className="facts"><dt>Native file</dt><dd>{download.filename}</dd><dt>Size</dt><dd>{new Intl.NumberFormat().format(download.size_bytes)} bytes</dd><dt>SHA-256</dt><dd className="identifier">{download.sha256}</dd></dl>
      <a className="button" href={download.content_path} download={download.filename}>Download native file</a>
    </>}
    <p className="notice">Downloaded copies are outside Asservat's automatic deletion. Follow your organization's handling and deletion policy.</p>
  </div>;
}
