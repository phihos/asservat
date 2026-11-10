import { OperationFailure, postOperation } from '../capture/http';
import type { components } from '../generated/processing-discovery';
import { validInput_search_processing_evidence, validOutput_search_processing_evidence } from '../generated/validate-processing-discovery';

export type DiscoveryQuery = components['schemas']['McpInput_search_processing_evidence'];
export type DiscoveryReply = components['schemas']['McpOutput_search_processing_evidence'];
export type DiscoveryPage = Extract<DiscoveryReply, { status: 'ok' }>['data'];
export interface ProcessingDiscoveryClient {
  search(query: DiscoveryQuery, csrf: string, signal: AbortSignal): Promise<DiscoveryReply>;
}

export const validDiscoveryQuery = validInput_search_processing_evidence;

export const processingDiscoveryClient: ProcessingDiscoveryClient = {
  async search(query, csrf, signal) {
    const reply = await postOperation('search_processing_evidence', query, csrf, signal, validDiscoveryQuery, validOutput_search_processing_evidence) as DiscoveryReply;
    if (reply.status !== 'ok') return reply;

    const { candidates, next } = reply.data;
    const caseSearch = 'case_id' in query;
    const validCursor = !next || (caseSearch ? !('anchor_at' in next) : 'anchor_at' in next);
    if (candidates.length > (query.limit ?? 12) || !validCursor) {
      throw new OperationFailure(502);
    }
    if (candidates.some(candidate => {
      if (query.purpose_ref !== undefined && candidate.purpose_ref !== query.purpose_ref) return true;
      if ('case_id' in query) return candidate.case_id !== query.case_id;
      const anchor = Date.parse(candidate.anchor_at);
      return candidate.cluster_id !== query.cluster_id || candidate.namespace_uid !== query.namespace_uid || candidate.workload_uid !== query.workload_uid ||
        !(Date.parse(query.acquired_from) <= anchor && anchor < Date.parse(query.acquired_until));
    })) throw new OperationFailure(502);
    return reply;
  },
};
