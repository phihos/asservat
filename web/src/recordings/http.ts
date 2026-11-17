import type { components as live } from '../generated/live';
import { validInput_list_recordings, validOutput_list_recordings } from '../generated/validate-live';
import { operations as captureOperations, postOperation, type Input as CaptureInput, type Output as CaptureOutput, type Preview } from '../capture/http';

// list_recordings is shared with live viewing and lives in the live bundle; a
// recording save is previewed by preview_capture with recording_handles.
export type Operation = 'list_recordings' | 'preview_capture';
export type Input<N extends Operation> = N extends 'preview_capture' ? CaptureInput<'preview_capture'> : live['schemas']['McpInput_list_recordings'];
export type Output<N extends Operation> = N extends 'preview_capture' ? CaptureOutput<'preview_capture'> : live['schemas']['McpOutput_list_recordings'];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type Target = Input<'list_recordings'>['target_ref'];
export type Recording = Data<'list_recordings'>['recordings'][number];
export type SavePreview = Preview;
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// Inventory and preview are passive operations. Submission uses the
// existing capture receipt, CSRF and same-key retry/resolve path.
export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    if (name === 'preview_capture') return captureOperations.call('preview_capture', input as CaptureInput<'preview_capture'>, csrf, signal) as Promise<Output<N>>;
    return postOperation(name, input, csrf, signal, validInput_list_recordings, validOutput_list_recordings, undefined, true) as Promise<Output<N>>;
  },
};
