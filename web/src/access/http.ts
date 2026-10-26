import type { components } from '../generated/access';
import * as validators from '../generated/validate-access';
import { postOperation } from '../capture/http';

export type Input = components['schemas']['McpInput_explain_access'];
export type Output = components['schemas']['McpOutput_explain_access'];
export type Explanation = Extract<Output, { status: 'ok' }>['data'];
export type AccessOperation = Input['operation'];
export interface Client {
  explain(input: Input, csrf: string, signal: AbortSignal): Promise<Output>;
}

// ADR-234: the caller's own access explanation, over the same
// session-authenticated, generated-contract operation request as captures.
export const client: Client = {
  explain(input: Input, csrf: string, signal: AbortSignal): Promise<Output> {
    return postOperation('explain_access', input, csrf, signal, validators.validInput_explain_access, validators.validOutput_explain_access) as Promise<Output>;
  },
};
