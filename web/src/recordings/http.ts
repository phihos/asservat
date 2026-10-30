import type { components } from '../generated/recordings';
import * as validators from '../generated/validate-recordings';
import { postOperation } from '../capture/http';

export type Operation = 'list_recordings' | 'preview_recording_save';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
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
    return postOperation(name, input, csrf, signal, validators[`validInput_${name}`], validators[`validOutput_${name}`], undefined, name === 'list_recordings') as Promise<Output<N>>;
  },
};
