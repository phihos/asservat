import type { components } from '../generated/capture';
import * as validators from '../generated/validate-capture';

export type Operation = 'list_diagnostics' | 'preview_capture' | 'request_capture' | 'resolve_capture_request' | 'get_capture';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type Target = NonNullable<Input<'preview_capture'>['target_ref']>;
export type Diagnostic = Data<'list_diagnostics'>['diagnostics'][number];
export type Preview = Data<'preview_capture'>;
export type Progress = Data<'get_capture'>;

export class OperationFailure extends Error {
  constructor(readonly status: number, readonly code = '', readonly detail = '') { super('Investigation request unavailable'); }
}
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// All five routes are fixed, local and session authenticated. Native evidence
// transfers have a different transport; this client only accepts metadata.
export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    const key = name === 'request_capture' || name === 'resolve_capture_request' ? (input as Input<'request_capture'>).idempotency_key : undefined;
    return postOperation(name, input, csrf, signal, validators[`validInput_${name}`], validators[`validOutput_${name}`], key) as Promise<Output<N>>;
  },
};

// postOperation is the one session-authenticated metadata operation request:
// generated input/output validation, CSRF, an optional identical
// Idempotency-Key header, 10 s and 32 KiB bounds, and no automatic replay.
export async function postOperation(name: string, input: unknown, csrf: string, signal: AbortSignal, validInput: (value: unknown) => boolean, validOutput: (value: unknown) => boolean, idempotencyKey?: string): Promise<unknown> {
  if (!validInput(input)) throw new OperationFailure(400);
  const request = new AbortController();
  const abort = () => request.abort();
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  const timer = setTimeout(abort, 10_000);
  try {
    const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf };
    if (idempotencyKey !== undefined) headers['Idempotency-Key'] = idempotencyKey;
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
    if (!validOutput(value)) throw new OperationFailure(502);
    const result = value as { data_class?: string; truncated?: boolean; next_cursor?: unknown };
    if (result.data_class !== 'metadata' || result.truncated || result.next_cursor !== null) throw new OperationFailure(502);
    return value;
  } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
}

export function operationMessage(error: unknown): string {
  // Only schema-validated canonical operation errors can provide this text.
  // HTTP/provider failures never pass their response body into the exception.
  if (error instanceof OperationFailure && error.detail) return error.detail;
  if (error instanceof OperationFailure && [401, 403, 404].includes(error.status)) return 'This request is unavailable or your access could not be checked. Check your access and try again.';
  if (error instanceof OperationFailure && error.status === 400) return 'Check the target and retention values, then try again.';
  return 'The investigation service is unavailable. Try again when the connection or service is restored.';
}
