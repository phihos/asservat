import { describe, expect, it } from 'vitest';
import { diffPlans, planFromPreview, planFromSettings, profileDefault, unchanged } from './plan-diff';
import { recordingPreviewResult, settingsResult } from './test-fixtures';
import type { Preview } from './http';

function preview(): Preview {
  const value = recordingPreviewResult();
  if (value.status !== 'ok') throw new Error('synthetic preview');
  return value.data;
}
const http = 'a005bdfce57635c5dabddbdd6', calls = 'a5b186fa2f944fc675c96fcc2', processes = 'adf187502ec3e8884310b85cf', sockets = 'a7e5c90417a8841bef4f7993c';

describe('plan diff (REQ-CPR-005)', () => {
  it('reports no changes for the same plan', () => {
    const plan = planFromPreview(preview())!;
    expect(unchanged(diffPlans(plan, planFromPreview(preview())!))).toBe(true);
  });

  it('reports changed fields, added/removed actions, bounds and ongoing versus per-incident costs', () => {
    const before = preview();
    const after = preview();
    const c = after.profile_composition!;
    c.authored.components[0].overrides = [{ actionID: 'http', field: 'packetFilter', value: 'tcp port 8443' }];
    c.authored.components[1].overrides = [{ actionID: 'syscalls', field: 'syscallMaxEvents', value: 5000 }];
    c.authored.components.pop(); // remove process-context
    c.authored.maxTotalBytes = 64 << 20;
    c.actionMap = c.actionMap.filter(a => a.componentID !== 'context');
    after.lifecycle_plan.actions = after.lifecycle_plan.actions.filter(a => a.actionID === http || a.actionID === calls);
    const life = after.lifecycle_plan.actions.find(a => a.actionID === calls)!;
    Object.assign(life, { executionMode: 'onTrigger', requestedBefore: '0s', after: '10s' });
    delete (life as { activation?: string }).activation;
    after.capture_assessment.actions = after.capture_assessment.actions.filter(a => a.actionID === http || a.actionID === calls);
    after.capture_assessment.actions[0].quantities[1].upper = 16 << 20; // ongoing ring memory of http
    after.approval_required = false;
    const diff = diffPlans(planFromPreview(before)!, planFromPreview(after)!);

    expect(diff.costsCompared).toBe(true);
    expect(diff.actions.find(a => a.actionID === http)).toEqual({ actionID: http, alias: 'http/http', status: 'changed', changes: [
      { label: 'Packet filter', before: 'tcp port 8080', after: 'tcp port 8443' },
      { label: 'Ongoing collector memory, per observed pod', before: '0 bytes–32 MiB (configured limit)', after: '0 bytes–16 MiB (configured limit)' },
    ] });
    expect(diff.actions.find(a => a.actionID === calls)!.changes).toEqual(expect.arrayContaining([
      { label: 'When recording starts', before: 'Ongoing; save on trigger', after: 'On trigger' },
      { label: 'History window', before: '30s', after: '0s' },
      { label: 'Event limit', before: profileDefault, after: '5000' },
    ]));
    expect(diff.actions.filter(a => a.status === 'removed').map(a => [a.actionID, a.alias])).toEqual([[processes, 'context/processes'], [sockets, 'context/sockets']]);
    expect(diff.bounds).toEqual([
      { label: 'Maximum total bytes', before: '96 MiB', after: '64 MiB' },
      { label: 'Profile context', before: 'builtin/process-context v1', after: 'Not included' },
    ]);
    expect(diff.costs).toContainEqual({ label: 'Needs approval', before: 'Yes', after: 'No' });
  });

  it('reports added actions and compares saved settings without inventing a cost baseline', () => {
    const current = preview();
    const saved = settingsResult();
    if (saved.status !== 'ok' || saved.data.kind !== 'captureSettings') throw new Error('synthetic settings');
    const original = structuredClone(current.profile_composition!);
    original.authored.components.splice(1, 1);
    original.actionMap = original.actionMap.filter(a => a.componentID !== 'calls');
    saved.data.settings.profile_composition = original;
    saved.data.settings.recipe_spec.actions = [{ id: http, kind: 'packetCapture', executionMode: 'ongoing', parameters: { before: '60s', after: '30s' } }] as never;
    const diff = diffPlans(planFromSettings(saved.data)!, planFromPreview(current)!);
    expect(diff.costsCompared).toBe(false);
    expect(diff.costs).toEqual([]);
    expect(diff.actions).toContainEqual({ actionID: calls, alias: 'calls/syscalls', status: 'added', changes: [] });
    expect(diff.actions.find(a => a.actionID === http)!.changes).toEqual([{ label: 'History window', before: '60s', after: '30s' }]);
    expect(diff.bounds).toContainEqual({ label: 'Profile calls', before: 'Not included', after: 'builtin/syscall-activity v1' });
  });
});
