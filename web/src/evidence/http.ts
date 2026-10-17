import type { components } from '../generated/evidence';
import * as validators from '../generated/validate-evidence';

export type Operation = 'get_case' | 'prepare_artifact_download' | 'get_artifact_download' | 'cancel_artifact_download';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type CaseDetails = Data<'get_case'>;
export type Artifact = CaseDetails['artifacts'][number];
export type Download = Data<'get_artifact_download'>;
export type CancellationReceipt = Exclude<Data<'cancel_artifact_download'>, { artifact_id: string }>;

export class OperationFailure extends Error {
  constructor(readonly status: number, readonly code = '', readonly detail = '') { super('Evidence request unavailable'); }
}
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// All four routes are fixed, local and session authenticated. Their presence in
// a generated client does not imply that the backend implements them. Native evidence
// transfers have a different transport; this client only accepts metadata.
export const operations: Operations = {
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    if (!validators[`validInput_${name}`](input)) throw new OperationFailure(400);
    const request = new AbortController();
    const abort = () => request.abort();
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const timer = setTimeout(abort, 10_000);
    try {
      const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf };
      if (name === 'prepare_artifact_download' || name === 'cancel_artifact_download') headers['Idempotency-Key'] = (input as Input<'prepare_artifact_download'>).idempotency_key;
      const response = await fetch('/api/v1/operations/' + name, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers, body: JSON.stringify(input), signal: request.signal,
      });
      if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
        await response.body?.cancel(); throw new OperationFailure(response.status === 200 ? 502 : response.status);
      }
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 32_768 || request.signal.aborted) throw new OperationFailure(502);
          chunks.push(value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      if (request.signal.aborted) throw new OperationFailure(503);
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!validators[`validOutput_${name}`](value)) throw new OperationFailure(502);
      const result = value as Output<N>;
      if (result.data_class !== 'metadata' || result.truncated || result.next_cursor !== null) throw new OperationFailure(502);
      return result;
    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
  },
};

export function operationMessage(error: unknown): string {
  // Only schema-validated canonical operation errors can provide this text.
  // HTTP/provider failures never pass their response body into the exception.
  if (error instanceof OperationFailure && error.detail) return error.detail;
  if (error instanceof OperationFailure && [401, 403, 404].includes(error.status)) return 'This request is unavailable or your access could not be checked. Check your access and try again.';
  if (error instanceof OperationFailure && error.status === 400) return 'This evidence request could not be accepted. Refresh the details and try again.';
  return 'The evidence service is unavailable. Your administrator can check whether evidence access and native downloads are enabled.';
}
