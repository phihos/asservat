import { Component, type ReactNode } from 'react';

// A failed lazy chunk must leave a usable recovery page, not a blank workspace.
// This component holds no evidence and never treats retry as download intent.
export class EvidenceBoundary extends Component<{ children: ReactNode; path: string }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <section><h1>Evidence view unavailable</h1><p role="alert">The evidence view could not be loaded. Reload this page to try again.</p><a className="button secondary" href={this.props.path}>Reload evidence view</a></section> : this.props.children;
  }
}
