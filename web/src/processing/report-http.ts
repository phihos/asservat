import { OperationFailure, postOperation } from '../capture/http';
import type { components } from '../generated/processing-report';
import { validInput_get_processing_report, validOutput_get_processing_report } from '../generated/validate-processing-report';

export type ProcessingReportQuery = components['schemas']['McpInput_get_processing_report'];
export type ProcessingReportReply = components['schemas']['McpOutput_get_processing_report'];
export type ProcessingReportResponse = Extract<ProcessingReportReply, { status: 'ok' }>;
export type ProcessingReportPage = ProcessingReportResponse['data'];
export type ProcessingReportExport = components['schemas']['ProcessingReportExport'];

export interface ProcessingReportClient {
  read(query: ProcessingReportQuery, csrf: string, signal: AbortSignal): Promise<ProcessingReportReply>;
}

export const processingReportClient: ProcessingReportClient = {
  async read(query, csrf, signal) {
    const reply = await postOperation('get_processing_report', query, csrf, signal,
      validInput_get_processing_report, validOutput_get_processing_report) as ProcessingReportReply;
    if (reply.status !== 'ok') return reply;
    const page = reply.data;
    const observed = Date.parse(page.observed_at), until = Date.parse(page.valid_until);
    if (page.section !== (query.section ?? 'artifacts') || page.records.length > (query.limit ?? 3) ||
      page.section !== 'processors' && page.next === undefined ||
      page.next?.section === page.section && page.records.length === 0 ||
      observed > Date.now() || Date.now() >= until || until - observed > 5000 ||
      query.created_before !== undefined && Date.parse(query.created_before) !== Date.parse(page.selection_created_before) ||
      query.policy_digest !== undefined && query.policy_digest !== page.policy_revision.digest ||
      page.next && (Date.parse(page.next.created_before!) !== Date.parse(page.selection_created_before) || page.next.policy_digest !== page.policy_revision.digest)) {
      throw new OperationFailure(502);
    }
    return reply;
  },
};
