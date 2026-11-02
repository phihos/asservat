import type { Data, Preview } from './http';

// Client-side before/after comparison of two profile-composition plans
// (REQ-CPR-005). It only restates fields the server already returned; it
// computes no cost, grants nothing and is never sent back to the server.

type Composition = NonNullable<Preview['profile_composition']>;
type Quantity = Preview['capture_assessment']['combinedQuantities'][number];
type SavedSettings = Extract<Data<'get_capture_settings'>, { kind: 'captureSettings' }>;

export type PlanAction = {
  alias: string;
  // Effective lifecycle settings; compared only when both plans report them.
  fields: Record<string, string>;
  // Authored edits; an absent edit means the profile's reviewed default.
  overrides: Record<string, string>;
  // Assessment of this action; present only for server previews.
  costs?: Record<string, string>;
};
export type PlanSnapshot = {
  actions: Record<string, PlanAction>;
  bounds: Record<string, string>;
  costs?: Record<string, string>;
};
export type PreviousPlan = { from: 'settings' | 'preview'; captureID?: string; plan: PlanSnapshot };
export type Change = { label: string; before?: string; after?: string };
export type ActionDiff = { actionID: string; alias: string; status: 'added' | 'removed' | 'changed'; changes: Change[] };
export type PlanDiff = { actions: ActionDiff[]; bounds: Change[]; costs: Change[]; costsCompared: boolean };

export const profileDefault = 'Profile default';
const overrideLabels: Record<string, string> = {
  packetPeers: 'Peers', packetFilter: 'Packet filter', packetRing: 'Ring', syscallFilter: 'System calls', syscallMode: 'System call mode',
  syscallRing: 'Ring', syscallArguments: 'Argument capture', syscallMaxEvents: 'Event limit', syscallRate: 'Event rate limit',
  actionMaxBytes: 'Output limit (bytes)', actionTimeout: 'Completion deadline', processSelector: 'Process selector', processBatch: 'Process batch',
  profileDuration: 'Profile duration', filePath: 'File path', commandArgv: 'Command',
};
// Windows and mode are reported as effective lifecycle fields instead.
const lifecycleOverrides = new Set(['packetBefore', 'packetAfter', 'syscallBefore', 'syscallAfter', 'actionExecutionMode']);
const recorders = new Set(['packetCapture', 'syscallTrace']);

function formatValue(field: string, value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (field === 'packetPeers' && value && typeof value === 'object' && Array.isArray((value as { entries?: unknown }).entries)) {
    const n = (value as { entries: unknown[] }).entries.length;
    return `${n} peer ${n === 1 ? 'entry' : 'entries'} (${JSON.stringify(value)})`;
  }
  return JSON.stringify(value);
}

function bytes(n: number): string {
  for (const [unit, size] of [['GiB', 1 << 30], ['MiB', 1 << 20], ['KiB', 1 << 10]] as const) if (n >= size && n % (size / 1024) === 0) return `${+(n / size).toFixed(2)} ${unit}`;
  return `${n} bytes`;
}
const dimensions: Record<Quantity['dimension'], [string, (n: number) => string]> = {
  applicationPauseMs: ['application pause', n => `${n} ms`], applicationCpuMillicores: ['application CPU', n => `${n} millicores`],
  collectorMemoryBytes: ['collector memory', bytes], outputBytes: ['output', bytes], uploadBytesPerSecond: ['upload rate', n => bytes(n) + '/s'],
  applicationLatencyPercent: ['application latency', n => `${n}%`], collectorStorageBytes: ['collector storage', bytes],
};
const scopes: Record<Quantity['scope'], string> = { perProcess: 'per process', perObservationPod: 'per observed pod', perIncidentPod: 'per incident pod', perNode: 'per node', wholePlan: 'whole plan' };
const bases: Record<Quantity['basis'], string> = { configuredLimit: 'configured limit', modelEstimate: 'model estimate', qualifiedMeasurement: 'measured' };

// Ongoing (while armed) and per-incident costs stay separate keys.
function quantities(values: Quantity[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const q of values) {
    const [name, format] = dimensions[q.dimension];
    let label = `${q.phase === 'whileArmed' ? 'Ongoing' : 'Per incident'} ${name}, ${scopes[q.scope]}`;
    if (label in out) label += ` (${q.sourceRef})`;
    out[label] = `${q.lower === q.upper ? format(q.upper) : `${format(q.lower)}–${format(q.upper)}`} (${bases[q.basis]})`;
  }
  return out;
}

function base(composition: Composition): PlanSnapshot {
  const actions: Record<string, PlanAction> = {};
  for (const entry of composition.actionMap) {
    const alias = `${entry.componentID}/${entry.localActionID}`;
    const action = actions[entry.actionID] ??= { alias, fields: {}, overrides: {} };
    if (action.alias !== alias) action.alias += ', ' + alias; // deduplicated aliases
    const component = composition.authored.components.find(c => c.id === entry.componentID);
    for (const o of component?.overrides ?? []) {
      if (o.actionID !== entry.localActionID || lifecycleOverrides.has(o.field)) continue;
      action.overrides[overrideLabels[o.field] ?? o.field] = formatValue(o.field, o.value);
    }
  }
  const bounds: Record<string, string> = {
    'Maximum total bytes': bytes(composition.authored.maxTotalBytes), 'Maximum duration': composition.authored.maxDuration,
  };
  for (const c of composition.authored.components) bounds[`Profile ${c.id}`] = `${c.profileRef.catalog}/${c.profileRef.name} ${c.profileRef.version}`;
  return { actions, bounds };
}

function lifecycle(mode: string, kind: string, before?: string, after?: string): Record<string, string> {
  const fields: Record<string, string> = { 'When recording starts': mode === 'ongoing' ? 'Ongoing; save on trigger' : 'On trigger' };
  if (recorders.has(kind)) {
    if (before !== undefined) fields['History window'] = before;
    if (after !== undefined) fields['Next interval'] = after;
  }
  return fields;
}

export function planFromPreview(preview: Preview): PlanSnapshot | undefined {
  if (!preview.profile_composition) return undefined;
  const plan = base(preview.profile_composition);
  for (const a of preview.lifecycle_plan.actions) {
    const action = plan.actions[a.actionID];
    if (action) action.fields = lifecycle(a.executionMode, a.kind, a.requestedBefore ?? (recorders.has(a.kind) ? '0s' : undefined), a.after);
  }
  for (const a of preview.capture_assessment.actions as Preview['capture_assessment']['actions']) {
    const action = plan.actions[a.actionID];
    if (action) action.costs = { Impact: a.impact.level, ...quantities(a.quantities) };
  }
  plan.costs = {
    'Pods selected': String(preview.pod_count), 'Saved evidence limit': bytes(preview.max_bytes),
    'Needs approval': preview.approval_required ? 'Yes' : 'No', 'Combined impact': preview.capture_assessment.combinedImpact.level,
    ...quantities(preview.capture_assessment.combinedQuantities),
  };
  return plan;
}

// The accepted settings of an earlier capture: authored edits and the
// expanded recipe, but no current assessment.
export function planFromSettings(saved: SavedSettings): PlanSnapshot | undefined {
  const composition = saved.settings.profile_composition;
  if (!composition) return undefined;
  const plan = base(composition);
  for (const a of saved.settings.recipe_spec.actions as { id: string; kind: string; executionMode?: string; parameters?: { before?: unknown; after?: unknown } }[]) {
    const action = plan.actions[a.id];
    const p = a.parameters ?? {};
    if (action) action.fields = lifecycle(a.executionMode ?? 'onTrigger', a.kind, typeof p.before === 'string' ? p.before : undefined, typeof p.after === 'string' ? p.after : undefined);
  }
  return plan;
}

function compare(before: Record<string, string>, after: Record<string, string>, absent?: string): Change[] {
  const labels = [...new Set([...Object.keys(before), ...Object.keys(after)])];
  return labels.flatMap(label => {
    const b = before[label] ?? absent, a = after[label] ?? absent;
    if (b === undefined || a === undefined || a === b) return [];
    return [{ label, before: b, after: a }];
  });
}

export function diffPlans(before: PlanSnapshot, after: PlanSnapshot): PlanDiff {
  const actions: ActionDiff[] = [];
  for (const [actionID, a] of Object.entries(after.actions)) {
    const b = before.actions[actionID];
    if (!b) { actions.push({ actionID, alias: a.alias, status: 'added', changes: [] }); continue; }
    const changes = [...compare(b.fields, a.fields), ...compare(b.overrides, a.overrides, profileDefault), ...(b.costs && a.costs ? compare(b.costs, a.costs, 'None') : [])];
    if (changes.length) actions.push({ actionID, alias: a.alias, status: 'changed', changes });
  }
  for (const [actionID, b] of Object.entries(before.actions)) if (!(actionID in after.actions)) actions.push({ actionID, alias: b.alias, status: 'removed', changes: [] });
  const costsCompared = !!(before.costs && after.costs);
  return { actions, bounds: compare(before.bounds, after.bounds, 'Not included'), costs: costsCompared ? compare(before.costs!, after.costs!, 'None') : [], costsCompared };
}

export function unchanged(diff: PlanDiff): boolean {
  return diff.actions.length === 0 && diff.bounds.length === 0 && diff.costs.length === 0;
}
