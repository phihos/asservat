import type { components } from '../generated/capacity';
import * as validators from '../generated/validate-capacity';
import { postOperation } from '../capture/http';

export type LiveCapacityInput = components['schemas']['McpInput_get_live_capacity'];
export type LiveCapacityOutput = components['schemas']['McpOutput_get_live_capacity'];
export type LiveCapacity = Extract<LiveCapacityOutput, { status: 'ok' }>['data'];
export interface LiveCapacityClient {
  read(clusterID: string, csrf: string, signal: AbortSignal): Promise<LiveCapacityOutput>;
}

export const validLiveCapacityInput = (value: unknown): value is LiveCapacityInput => validators.validInput_get_live_capacity(value);

export const liveCapacityClient: LiveCapacityClient = {
  read(clusterID: string, csrf: string, signal: AbortSignal): Promise<LiveCapacityOutput> {
    const input: LiveCapacityInput = { cluster_id: clusterID };
    return postOperation('get_live_capacity', input, csrf, signal, validators.validInput_get_live_capacity, validators.validOutput_get_live_capacity) as Promise<LiveCapacityOutput>;
  },
};
