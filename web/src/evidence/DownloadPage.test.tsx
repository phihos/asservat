import { render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { DownloadPage } from './DownloadPage';
import { SyntheticEvidence, completed, downloadResult, id, preparing, session } from './test-fixtures';

it('starts the Ready session in the signed-in browser', async () => {
  const client = new SyntheticEvidence(); const start = vi.fn();
  render(<DownloadPage session={session} scope={new AbortController().signal} downloadID={id(4)} client={client} start={start}/>);
  expect(await screen.findByRole('link', { name: 'Download native file' })).toBeTruthy();
  expect(client.calls[0].input).toEqual({ action: 'status', download_id: id(4) });
  expect(start).toHaveBeenCalledWith(`/api/v1/downloads/${id(4)}/content`);
});
it('waits on a Preparing session with after_revision, then starts it', async () => {
  const client = new SyntheticEvidence(); const start = vi.fn(); let first = true;
  client.responder = () => first ? (first = false, preparing()) : downloadResult();
  render(<DownloadPage session={session} scope={new AbortController().signal} downloadID={id(4)} client={client} start={start}/>);
  await waitFor(() => expect(start).toHaveBeenCalled());
  expect(client.calls.map(c => c.input)).toEqual([{ action: 'status', download_id: id(4) }, { action: 'status', download_id: id(4), after_revision: 1 }]);
});
it('shows an ended session without starting it', async () => {
  const client = new SyntheticEvidence(); client.responder = () => completed(); const start = vi.fn();
  render(<DownloadPage session={session} scope={new AbortController().signal} downloadID={id(4)} client={client} start={start}/>);
  expect(await screen.findByText(/This download ended: Completed/)).toBeTruthy();
  expect(start).not.toHaveBeenCalled();
});
