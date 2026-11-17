import type { components } from '../generated/policy-legacy';
import * as validators from '../generated/validate-policy-legacy';
import { postOperation } from '../capture/http';

// activate_policy and request_policy_grant keep their legacy contract until
// hub-side acceptance (specs/policy-automation.md) replaces them.
export type Operation = 'activate_policy' | 'request_policy_grant';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    return postOperation(name, input, csrf, signal, validators[`validInput_${name}`], validators[`validOutput_${name}`], (input as Input<'activate_policy'>).idempotency_key) as Promise<Output<N>>;
  },
};
