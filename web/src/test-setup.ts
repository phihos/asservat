// jsdom has no EventSource. Tests drive status streams through this fake.
export class FakeEventSource extends EventTarget {
  static instances: FakeEventSource[] = [];
  closed = false;
  constructor(readonly url: string) { super(); FakeEventSource.instances.push(this); }
  close() { this.closed = true; }
  emit(type: string, data: unknown) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
}
globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
