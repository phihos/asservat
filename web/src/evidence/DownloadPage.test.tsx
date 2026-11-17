import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { DownloadPage } from './DownloadPage';
import { SyntheticEvidence, failure, id, session } from './test-fixtures';

it('starts the Ready session in the signed-in browser', async () => {
  const client = new SyntheticEvidence(); const start = vi.fn();
  render(<DownloadPage session={session} scope={new AbortController().signal} downloadID={id(4)} client={client} start={start}/>);
  expect(await screen.findByRole('link', { name: 'Download native file' })).toBeTruthy();
  expect(client.calls[0].input).toEqual({ action: 'status', download_id: id(4) });
  expect(start).toHaveBeenCalledWith(`/api/v1/downloads/${id(4)}/content`);
});
it('shows an ended session without starting it', async () => {
  const client = new SyntheticEvidence(); client.responder = () => failure('CapabilityUnavailable', 'This download session ended: Completed.'); const start = vi.fn();
  render(<DownloadPage session={session} scope={new AbortController().signal} downloadID={id(4)} client={client} start={start}/>);
  expect(await screen.findByText('This download session ended: Completed.')).toBeTruthy();
  expect(start).not.toHaveBeenCalled();
});
