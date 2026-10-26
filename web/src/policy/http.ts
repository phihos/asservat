import type { components } from '../generated/policy';
import * as validators from '../generated/validate-policy';
import { postOperation } from '../capture/http';

export type Operation = 'activate_policy' | 'deactivate_policy' | 'get_policy_status';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type Status = Data<'get_policy_status'>;
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// The three ADR-228/229 policy routes use the same session-authenticated,
// generated-contract request as captures. The server checks every call.
export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    const key = name === 'get_policy_status' ? undefined : (input as Input<'activate_policy'>).idempotency_key;
    return postOperation(name, input, csrf, signal, validators[`validInput_${name}`], validators[`validOutput_${name}`], key) as Promise<Output<N>>;
  },
};
