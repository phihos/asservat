import { existsSync, readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { validInput_query_artifact, validOutput_query_artifact } from '../generated/validate-projection';

const example = (name: string) => JSON.parse(readFileSync(existsSync(new URL('../../../examples/implemented/' + name, import.meta.url)) ? new URL('../../../examples/implemented/' + name, import.meta.url) : new URL('../../../examples/' + name, import.meta.url), 'utf8'));

it.each(['metadata', 'raw'])('accepts the same canonical %s query and primitive page as Go', kind => {
  expect(validInput_query_artifact(example(`mcp-packet-query-${kind}-input.json`))).toBe(true);
  expect(validOutput_query_artifact(example(`mcp-packet-query-${kind}-result.json`))).toBe(true);
});

it('keeps metadata ordinary and requires the declared raw-prefix selection', () => {
  const metadata = example('mcp-packet-query-metadata-input.json');
  expect(metadata.grant_id).toBeUndefined();
  expect(validInput_query_artifact(metadata)).toBe(true);
  expect(validInput_query_artifact({ ...metadata, fields: ['frame_prefix_hex'] })).toBe(false);
  expect(validInput_query_artifact({ ...metadata, fields: ['secret_payload'] })).toBe(false);
  expect(validInput_query_artifact({ ...metadata, display_filter: 'tcp.port == 80' })).toBe(false);
});

it('preserves zero and null but rejects boolean or tagged cells and class downgrade', () => {
  const raw = example('mcp-packet-query-raw-result.json');
  expect(raw.data.rows[0][1]).toBe(0);
  expect(raw.data.rows[1][1]).toBeNull();
  for (const value of [false, true, { number: 0 }, -1]) {
    const changed = structuredClone(raw);
    changed.data.rows[0][1] = value;
    expect(validOutput_query_artifact(changed)).toBe(false);
  }
  expect(validOutput_query_artifact({ ...raw, data_class: 'extract' })).toBe(false);
  expect(validOutput_query_artifact({ ...raw, data: { ...raw.data, capture_mode: 'networkHeaders' } })).toBe(false);
});

it('allows at most one logical stop reason', () => {
  const raw = example('mcp-packet-query-raw-result.json');
  for (const flag of ['row_limit_reached', 'scan_limit_reached', 'output_limit_reached']) {
    expect(validOutput_query_artifact({ ...raw, data: { ...raw.data, [flag]: true } })).toBe(true);
  }
  expect(validOutput_query_artifact({ ...raw, data: { ...raw.data, row_limit_reached: true, scan_limit_reached: true } })).toBe(false);
});
