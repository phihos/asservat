import type { components } from '../generated/retention-preview';
import * as validators from '../generated/validate-retention-preview';
import { postOperation } from '../capture/http';

export type RetentionPreviewInput = components['schemas']['McpInput_preview_retention_change'];
export type RetentionPreviewOutput = components['schemas']['McpOutput_preview_retention_change'];
export type RetentionPreview = Extract<RetentionPreviewOutput, { status: 'ok' }>['data'];
export interface RetentionPreviewClient {
  preview(input: RetentionPreviewInput, csrf: string, signal: AbortSignal): Promise<RetentionPreviewOutput>;
}

export const validRetentionPreviewInput = (value: unknown): value is RetentionPreviewInput => validators.validInput_preview_retention_change(value);

// ADR-240: the fleet operator's retention impact preview, a browser-only
// operation over the same session-authenticated, generated-contract request.
export const retentionPreviewClient: RetentionPreviewClient = {
  preview(input: RetentionPreviewInput, csrf: string, signal: AbortSignal): Promise<RetentionPreviewOutput> {
    return postOperation('preview_retention_change', input, csrf, signal, validators.validInput_preview_retention_change, validators.validOutput_preview_retention_change) as Promise<RetentionPreviewOutput>;
  },
};
