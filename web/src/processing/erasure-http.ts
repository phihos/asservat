import { OperationFailure, postOperation } from '../capture/http';
import type { components } from '../generated/processing-erasure';
import { validInput_get_processing_erasure, validOutput_get_processing_erasure } from '../generated/validate-processing-erasure';

export type ErasureStatusReply = components['schemas']['McpOutput_get_processing_erasure'];
export type ErasureStatus = Extract<ErasureStatusReply, { status: 'ok' }>['data'];
export interface ProcessingErasureClient {
  read(requestID: string, csrf: string, signal: AbortSignal): Promise<ErasureStatusReply>;
}

export const processingErasureClient: ProcessingErasureClient = {
  async read(requestID, csrf, signal) {
    const reply = await postOperation('get_processing_erasure', { request_id: requestID }, csrf, signal,
      validInput_get_processing_erasure, validOutput_get_processing_erasure) as ErasureStatusReply;
    if (reply.status === 'ok' && reply.data.request_id !== requestID) throw new OperationFailure(502);
    return reply;
  },
};
