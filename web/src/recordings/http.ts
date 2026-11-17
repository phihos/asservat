import type { components } from '../generated/recordings';
import type { components as live } from '../generated/live';
import * as validators from '../generated/validate-recordings';
import { validInput_list_recordings, validOutput_list_recordings } from '../generated/validate-live';
import { postOperation } from '../capture/http';

export type Operation = 'list_recordings' | 'preview_recording_save';
// list_recordings is shared with live viewing and lives in the live bundle.
export type Input<N extends Operation> = N extends 'list_recordings' ? live['schemas']['McpInput_list_recordings'] : components['schemas']['McpInput_preview_recording_save'];
export type Output<N extends Operation> = N extends 'list_recordings' ? live['schemas']['McpOutput_list_recordings'] : components['schemas']['McpOutput_preview_recording_save'];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type Recording = Data<'list_recordings'>['recordings'][number];
export type SavePreview = Data<'preview_recording_save'>;
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// Inventory and preview are passive metadata operations. Submission uses the
// existing capture receipt, CSRF and same-key retry/resolve path.
export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    const list = name === 'list_recordings';
    return postOperation(name, input, csrf, signal, list ? validInput_list_recordings : validators.validInput_preview_recording_save, list ? validOutput_list_recordings : validators.validOutput_preview_recording_save, undefined, list) as Promise<Output<N>>;
  },
};
