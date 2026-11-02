import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CaptureWorkspace } from './CaptureWorkspace';
import { Investigation } from './investigation';
import { SaveAsProfile } from './SaveAsProfile';
import { SyntheticOperations, catalogResult, historyResult, id, profileResult, profilesResult, recordingPreviewResult, result, session, target } from './test-fixtures';
import type { Preview } from './http';

const controllers: Investigation[] = [];
afterEach(() => { cleanup(); for (const c of controllers) c.reset(); controllers.length = 0; vi.unstubAllGlobals(); });

function recording(filter: string): ReturnType<typeof recordingPreviewResult> {
  const value = recordingPreviewResult();
  if (value.status !== 'ok') throw new Error('synthetic preview');
  value.data.profile_composition!.authored.components[0].overrides = [{ actionID: 'http', field: 'packetFilter', value: filter }];
  return value;
}

it('returns to the composer with its edits and shows a before/after diff of the re-reviewed plan (REQ-CPR-005)', async () => {
  const client = new SyntheticOperations(); const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  let preview = recording('tcp port 8080');
  client.responder = name => name === 'list_diagnostics' ? catalogResult() : name === 'list_capture_history' ? historyResult([]) : name === 'list_capture_profiles' ? profilesResult()
    : name === 'get_capture_profile' ? profileResult('network-connections') : preview;
  render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: target.cluster_id } });
  fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: target.namespace } });
  fireEvent.change(screen.getByLabelText('Workload or pod name'), { target: { value: target.name } });
  fireEvent.click(screen.getByRole('button', { name: 'Find diagnostics' }));
  fireEvent.click((await screen.findAllByRole('button', { name: 'Add profile' }))[0]);
  fireEvent.change(await screen.findByLabelText(/Next interval/), { target: { value: '5s' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
  await screen.findByRole('heading', { name: 'Review collection' });
  expect(screen.queryByRole('heading', { name: 'Changes from the previous plan' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Change profiles' }));
  const after = await screen.findByLabelText(/Next interval/);
  expect((after as HTMLInputElement).value).toBe('5s');
  preview = recording('tcp port 8443');
  fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
  const heading = await screen.findByRole('heading', { name: 'Changes from the previous plan' });
  const panel = heading.closest('section')!;
  const table = within(panel).getByRole('table', { name: 'Changes to http/http' });
  const row = within(table).getByRole('rowheader', { name: 'Packet filter' }).closest('tr')!;
  expect([...row.querySelectorAll('td')].map(td => td.textContent)).toEqual(['tcp port 8080', 'tcp port 8443']);
  expect(within(panel).getByText(/previous review of this target/)).toBeTruthy();
  expect(client.calls.filter(c => c.name === 'preview_capture')).toHaveLength(2);
  expect(client.calls.some(c => c.name === 'request_capture')).toBe(false);
  // Three profiles cannot become one profile version.
  expect(screen.queryByRole('heading', { name: 'Save as profile' })).toBeNull();
});

it('compares an edited history repeat with the saved settings', async () => {
  const client = new SyntheticOperations(); const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  const saved = (await import('./test-fixtures')).settingsResult();
  const original = recording('tcp port 8080');
  if (saved.status !== 'ok' || saved.data.kind !== 'captureSettings' || original.status !== 'ok') throw new Error();
  saved.data.settings.profile_composition = original.data.profile_composition;
  client.responder = name => name === 'list_diagnostics' ? catalogResult() : name === 'list_capture_history' ? historyResult([id(41)]) : name === 'list_capture_profiles' ? profilesResult()
    : name === 'get_capture_settings' ? saved : (() => { const p = recording('tcp port 9090'); if (p.status === 'ok') p.data.repeated_from_capture_id = id(41); return p; })();
  act(() => controller.setDraft({ target, retention: '' }));
  await act(async () => { await controller.discover(); });
  await act(async () => { await controller.showSettings(id(41)); });
  const edited = structuredClone(original.data.profile_composition!.authored);
  edited.components[0].overrides![0].value = 'tcp port 9090';
  await act(async () => { await controller.previewComposition(edited, id(41)); });
  const panel = (await screen.findByRole('heading', { name: 'Changes from the previous plan' })).closest('section')!;
  expect(within(panel).getByText(id(41))).toBeTruthy();
  expect(within(panel).getByText(/carry no cost assessment/)).toBeTruthy();
  expect(within(panel).getByRole('rowheader', { name: 'Packet filter' }).closest('tr')!.textContent).toContain('tcp port 9090');
});

it('renders a CaptureProfile manifest with a new version and a create-only publish command', async () => {
  const client = new SyntheticOperations();
  client.responder = name => name === 'get_capture_profile' ? profileResult('network-connections')
    : result<'list_capture_profiles'>({ profiles: ['v1', 'v2'].map(version => ({ profile_ref: { catalog: 'namespace', name: 'network-connections', version }, display_name: 'Local', description: 'Local', available: true, deprecated: false, approval_required: false, blockers: [], execution_modes: ['ongoing'] })) });
  const writeText = vi.fn(async () => {});
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  const composition: NonNullable<Preview['profile_composition']> = {
    authored: { components: [{ id: 'net', profileRef: { catalog: 'builtin', name: 'network-connections', version: 'v1' }, overrides: [{ actionID: 'sample', field: 'packetFilter', value: 'tcp port 8443' }] }], maxTotalBytes: 8 << 20, maxDuration: '15s' } as never,
    resolvedProfiles: [{ componentID: 'net', profileRef: { catalog: 'builtin', name: 'network-connections', version: 'v1' }, definitionDigest: 'a'.repeat(64) }],
    actionMap: [{ componentID: 'net', localActionID: 'sample', actionID: 'a' + '1'.repeat(24), deduplicated: false }],
  };
  render(<SaveAsProfile session={session} scope={new AbortController().signal} target={target} composition={composition} client={client}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Save as profile…' }));
  const version = await screen.findByLabelText('New version');
  expect((version as HTMLInputElement).value).toBe('v3');
  expect(client.calls.map(c => [c.name, (c.input as { catalog?: string }).catalog])).toEqual([['get_capture_profile', undefined], ['list_capture_profiles', 'namespace']]);
  const manifest = JSON.parse(screen.getByRole('region', { name: 'CaptureProfile manifest' }).textContent!);
  expect(manifest).toMatchObject({ apiVersion: 'asservat.io/v1alpha1', kind: 'CaptureProfile', metadata: { name: 'network-connections.v3', namespace: 'payments' }, spec: { name: 'network-connections', version: 'v3' } });
  expect(manifest.spec.definition.recipe.actions[0].parameters.filter).toBe('tcp port 8443');
  expect(screen.getByRole('region', { name: 'Publish command' }).textContent).toBe('kubectl create -f network-connections.v3.json -n payments');
  expect(screen.getByText(/never overwritten/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Copy manifest' }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith(JSON.stringify(manifest, null, 2) + '\n'));
  expect(await screen.findByText('Manifest copied.')).toBeTruthy();
  fireEvent.change(version, { target: { value: 'v2' } });
  expect(screen.getByRole('alert').textContent).toMatch(/already exists/);
  expect(screen.queryByRole('region', { name: 'CaptureProfile manifest' })).toBeNull();
});
