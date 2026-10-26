import type { components } from '../generated/sharing';
import * as validators from '../generated/validate-sharing';
import { postOperation } from '../capture/http';

export type Operation = 'create_share' | 'list_shares' | 'revoke_share';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type ShareRow = Data<'list_shares'>['shares'][number];
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// The three ADR-232 share routes use the same session-authenticated,
// generated-contract request as captures and policies. The server checks
// eligibility, ownership and recipients on every call.
export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    const key = name === 'list_shares' ? undefined : (input as Input<'create_share'>).idempotency_key;
    return postOperation(name, input, csrf, signal, validators[`validInput_${name}`], validators[`validOutput_${name}`], key) as Promise<Output<N>>;
  },
};
