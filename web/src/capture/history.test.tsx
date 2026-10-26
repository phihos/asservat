import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { CaptureWorkspace } from './CaptureWorkspace';
import { Investigation, historyPageSize } from './investigation';
import { SyntheticOperations, session, target, id, historyResult, repeatedPreviewResult, previewResult, result } from './test-fixtures';
import type { Operation } from './http';

// ADR-236: Recent captures and Collect again. The synthetic client is not
// authority; the server decides visibility and runs every current check.
const controllers: Investigation[] = [];
afterEach(() => { cleanup(); for (const c of controllers) c.reset(); controllers.length = 0; window.history.replaceState(null, '', '/'); });
async function discovered(history = [id(41), id(42)]) {
  const client = new SyntheticOperations();
  const base = client.responder;
  client.responder = (name: Operation) => {
    if (name === 'list_capture_history') return historyResult(history);
    const repeated = (client.calls.at(-1)?.input as { history_capture_id?: string }).history_capture_id;
    return name === 'preview_capture' && repeated ? repeatedPreviewResult(repeated) : base(name);
  };
  const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  controller.attach(session, new AbortController().signal);
  controller.setDraft({ target, retention: '60' });
  await controller.discover();
  return { client, controller };
}

it('lists recent captures of the draft target after its diagnostics', async () => {
  const { client, controller } = await discovered();
  expect(client.calls.map(call => call.name)).toEqual(['list_diagnostics', 'list_capture_history']);
  expect(client.calls[1].input).toEqual({ target_ref: target, limit: historyPageSize });
  expect(controller.snapshot()).toMatchObject({ stage: 'diagnostics', historyMessage: undefined });
  expect(controller.snapshot().history?.map(entry => entry.capture_id)).toEqual([id(41), id(42)]);
});

it('keeps diagnostics usable when history is unavailable', async () => {
  const client = new SyntheticOperations();
  const base = client.responder;
  client.responder = (name: Operation) => {
    if (name !== 'list_capture_history') return base(name);
    const value = result<'list_capture_history'>({ code: 'NotAvailable', message: 'The operation is unavailable.', retryable: true });
    (value as { status: string }).status = 'error';
    return value;
  };
  const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  controller.attach(session, new AbortController().signal);
  controller.setDraft({ target, retention: '' }); await controller.discover();
  expect(controller.snapshot()).toMatchObject({ stage: 'diagnostics', error: undefined, historyMessage: 'The operation is unavailable.', history: undefined });
  expect(controller.snapshot().diagnostics).toHaveLength(1);
});

it('collects again through a fresh reviewed preview of only the history entry', async () => {
  const { client, controller } = await discovered();
  await controller.repeat(id(42));
  const preview = client.calls.filter(call => call.name === 'preview_capture');
  expect(preview).toHaveLength(1);
  expect(preview[0].input).toEqual({ history_capture_id: id(42) });
  expect(controller.snapshot()).toMatchObject({ stage: 'review', repeatedFrom: id(42) });
  await controller.submit();
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toEqual({ preview_id: id(173), idempotency_key: id(6) });
});

it('rejects a repeat review for another capture and an ordinary review claiming a repeat', async () => {
  const { client, controller } = await discovered();
  client.responder = () => repeatedPreviewResult(id(99));
  await controller.repeat(id(42));
  expect(controller.snapshot().stage).toBe('diagnostics');
  expect(controller.snapshot().error).toMatch(/could not be verified/);
  await controller.preview(controller.snapshot().diagnostics![0]);
  expect(controller.snapshot().stage).toBe('diagnostics');
  client.responder = () => previewResult();
  await controller.preview(controller.snapshot().diagnostics![0]);
  expect(controller.snapshot()).toMatchObject({ stage: 'review', repeatedFrom: undefined });
});

it('renders the Recent captures panel with Collect again', async () => {
  const client = new SyntheticOperations();
  const base = client.responder;
  client.responder = (name: Operation) => name === 'list_capture_history' ? historyResult([id(41)]) : name === 'preview_capture' ? repeatedPreviewResult(id(41)) : base(name);
  const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: target.cluster_id } });
  fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: target.namespace } });
  fireEvent.change(screen.getByLabelText('Workload or pod name'), { target: { value: target.name } });
  fireEvent.click(screen.getByRole('button', { name: 'Find diagnostics' }));
  expect(await screen.findByRole('heading', { name: 'Recent captures' })).toBeTruthy();
  fireEvent.click(await screen.findByRole('button', { name: 'Collect again' }));
  await screen.findByRole('heading', { name: 'Review collection' });
  expect(screen.getByText(/Collecting again with the settings of capture/)).toBeTruthy();
  expect(client.calls.find(call => call.name === 'preview_capture')!.input).toEqual({ history_capture_id: id(41) });
});
