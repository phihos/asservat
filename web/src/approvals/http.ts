import type { components } from '../generated/approvals';
import * as validators from '../generated/validate-approvals';
import { postOperation } from '../capture/http';

export type Operation = 'get_grant' | 'list_reviews' | 'decide_review' | 'revoke_grant';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Data<N extends Operation> = Extract<Output<N>, { status: 'ok' }>['data'];
export type Grant = Data<'get_grant'>;
export type ReviewRow = Data<'list_reviews'>['approvals'][number];
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// ADR-249: the approval inbox and decisions use the same
// session-authenticated, generated-contract request as captures. The server
// checks the approver role, self-approval and step-up on every call.
export const operations: Operations = {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    const key = name === 'decide_review' || name === 'revoke_grant' ? (input as Input<'decide_review'>).idempotency_key : undefined;
    return postOperation(name, input, csrf, signal, validators[`validInput_${name}`], validators[`validOutput_${name}`], key) as Promise<Output<N>>;
  },
};
