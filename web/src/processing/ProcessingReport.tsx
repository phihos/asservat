import { useLayoutEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { OperationFailure } from '../capture/http';
import { validProcessingReportExport } from '../generated/validate-processing-report';
import { processingReportClient, type ProcessingReportClient, type ProcessingReportExport, type ProcessingReportPage, type ProcessingReportQuery, type ProcessingReportResponse } from './report-http';

const pagesPerPart = 32;
type ReportSelection = Pick<ProcessingReportPage, 'root_id' | 'installation_id' | 'policy_revision' | 'selection_created_before'>;
type ReportContinuation = { query: ProcessingReportQuery; part: number; selection: ReportSelection };

export function ProcessingReport({ session, scope, disabled, client = processingReportClient }: {
  session: Session; scope: AbortSignal; disabled: boolean; client?: ProcessingReportClient;
}) {
  const running = useRef<AbortController | undefined>(undefined);
  const currentSession = useRef(session);
  currentSession.current = session;
  const [busy, setBusy] = useState(false);
  const [continuation, setContinuation] = useState<ReportContinuation>();
  const [status, setStatus] = useState<string>();
  const [error, setError] = useState<string>();

  useLayoutEffect(() => {
    const clear = () => {
      running.current?.abort();
      running.current = undefined;
      setBusy(false);
      setContinuation(undefined);
      setStatus(undefined);
      setError(undefined);
    };
    clear();
    scope.addEventListener('abort', clear, { once: true });
    return () => {
      running.current?.abort();
      running.current = undefined;
      scope.removeEventListener('abort', clear);
    };
  }, [scope]);

  const exportPart = async (start?: ReportContinuation) => {
    if (disabled || scope.aborted || running.current) return;
    const controller = new AbortController();
    running.current = controller;
    const abort = () => controller.abort();
    scope.addEventListener('abort', abort, { once: true });
    const current = () => running.current === controller && !controller.signal.aborted && !scope.aborted;
    setBusy(true);
    setError(undefined);
    setStatus('Exporting report…');
    if (!start) setContinuation(undefined);
    const pages: ProcessingReportResponse[] = [];
    const seen = new Set<string>();
    let query: ProcessingReportQuery | undefined = start?.query ?? { section: 'artifacts', limit: 3 };
    try {
      while (query && pages.length < pagesPerPart) {
        const key = JSON.stringify(query);
        if (seen.has(key)) throw new OperationFailure(502);
        seen.add(key);
        const reply = await client.read(query, currentSession.current.csrf_token, controller.signal);
        if (!current()) return;
        if (reply.status !== 'ok') throw new OperationFailure(503);
        const first = pages[0]?.data ?? start?.selection;
        if (first && (reply.data.root_id !== first.root_id || reply.data.installation_id !== first.installation_id ||
          reply.data.policy_revision.uid !== first.policy_revision.uid || reply.data.policy_revision.generation !== first.policy_revision.generation ||
          reply.data.policy_revision.digest !== first.policy_revision.digest ||
          Date.parse(reply.data.selection_created_before) !== Date.parse(first.selection_created_before))) throw new OperationFailure(502);
        pages.push(reply);
        query = reply.data.next;
      }
      if (!current()) return;
      const first = pages[0].data;
      const part = start?.part ?? 1;
      const value: ProcessingReportExport = {
        format: 'asservat-processing-inventory/v1', part,
        selection_created_before: first.selection_created_before, policy_revision: first.policy_revision,
        pages, ...(query ? { next: query } : {}), complete: query === undefined,
      };
      if (!validProcessingReportExport(value)) throw new OperationFailure(502);
      const body = JSON.stringify(value);
      if (new TextEncoder().encode(body).byteLength > 1024 * 1024) throw new OperationFailure(502);
      const url = URL.createObjectURL(new Blob([body], { type: 'application/json' }));
      try {
        const link = document.createElement('a');
        link.href = url;
        link.download = `asservat-processing-inventory-${first.selection_created_before.replaceAll(/[^0-9TZ]/g, '')}-part-${part}.json`;
        link.click();
      } finally { setTimeout(() => URL.revokeObjectURL(url), 0); }
      setContinuation(query ? { query, part: part + 1, selection: {
        root_id: first.root_id, installation_id: first.installation_id,
        policy_revision: first.policy_revision, selection_created_before: first.selection_created_before,
      } } : undefined);
      setStatus(query ? 'Report part exported. More report pages remain.' : 'Inventory export complete.');
    } catch (failure) {
      if (current()) {
        setStatus(undefined);
        setError(failure instanceof OperationFailure && [401, 403].includes(failure.status)
          ? 'Current privacy operator access is required.'
          : 'Inventory export is unavailable. Check current access and configuration, then start a new export.');
      }
    } finally {
      scope.removeEventListener('abort', abort);
      if (running.current === controller) {
        running.current = undefined;
        setBusy(false);
      }
    }
  };

  return <section className="review-section" aria-labelledby="processing-report-heading" aria-busy={busy}>
    <h2 id="processing-report-heading">Processing inventory report</h2>
    <p>Export retained artifact, sharing, download and operation records, processing rules, current technical locations and operator-declared processor organizations. Each page records its observation time. Client receipt remains unknown.</p>
    <p>Large reports download in parts. Continue until the final part to cover every section. Exported copies remain outside Asservat’s managed deletion.</p>
    <Button className="button secondary" isDisabled={disabled || busy || scope.aborted} onPress={() => void exportPart()}>Export inventory report</Button>
    {continuation && <Button className="button" isDisabled={disabled || busy || scope.aborted} onPress={() => void exportPart(continuation)}>Export next report part</Button>}
    {status && <p role="status">{status}</p>}
    {error && <p role="alert" className="notice">{error}</p>}
  </section>;
}
