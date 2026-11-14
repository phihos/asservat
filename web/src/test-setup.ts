// jsdom has no EventSource. Tests drive status streams through this fake.
export class FakeEventSource extends EventTarget {
  static readonly CONNECTING = 0; static readonly OPEN = 1; static readonly CLOSED = 2;
  static instances: FakeEventSource[] = [];
  closed = false;
  readyState = 1;
  constructor(readonly url: string) { super(); FakeEventSource.instances.push(this); }
  close() { this.closed = true; this.readyState = 2; }
  fail() { this.readyState = 2; this.dispatchEvent(new Event('error')); }
  emit(type: string, data: unknown) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
}
globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
