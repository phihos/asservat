import type { components } from '../generated/access-preview';
import * as validators from '../generated/validate-access-preview';
import { postOperation } from '../capture/http';

export type PreviewInput = components['schemas']['McpInput_preview_access_change'];
export type PreviewOutput = components['schemas']['McpOutput_preview_access_change'];
export type Preview = Extract<PreviewOutput, { status: 'ok' }>['data'];
export interface PreviewClient {
  preview(input: PreviewInput, csrf: string, signal: AbortSignal): Promise<PreviewOutput>;
}

export const validPreviewInput = (value: unknown): value is PreviewInput => validators.validInput_preview_access_change(value);

// ADR-237: the fleet operator's permission impact preview, a browser-only
// operation over the same session-authenticated, generated-contract request.
export const previewClient: PreviewClient = {
  preview(input: PreviewInput, csrf: string, signal: AbortSignal): Promise<PreviewOutput> {
    return postOperation('preview_access_change', input, csrf, signal, validators.validInput_preview_access_change, validators.validOutput_preview_access_change) as Promise<PreviewOutput>;
  },
};
