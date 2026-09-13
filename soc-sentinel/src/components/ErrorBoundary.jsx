import { Component } from 'react';
import { AlertOctagon } from 'lucide-react';

/**
 * Catches a render crash and shows what broke.
 *
 * React unmounts the whole tree when a component throws and nothing catches
 * it, so a single bad property access anywhere produced a blank white page —
 * no message, no clue, indistinguishable from a server being down or a port
 * not forwarded. That cost real debugging time chasing the network when the
 * fault was in the render.
 *
 * A dashboard that reports "the AI did not check these events" and then fails
 * silently in its own UI is contradicting itself. Failures are stated here the
 * same way findings are.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
    // Keep the real stack in the console for anyone with devtools open.
    console.error('Dashboard render error:', error, info?.componentStack);
  }

  render() {
    const { error, info } = this.state;
    if (!error) return this.props.children;

    const where = this.props.label ? ` in ${this.props.label}` : '';
    return (
      <div className="p-6">
        <div className="max-w-3xl bg-card border border-red-500/40 rounded-lg overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-red-500/10 border-b border-red-500/30">
            <AlertOctagon size={15} className="text-red-400" />
            <span className="text-red-400 text-sm font-medium">
              This view crashed{where}
            </span>
            <button
              onClick={() => this.setState({ error: null, info: null })}
              className="ml-auto px-2 py-0.5 bg-hover border border-border rounded text-[10px] text-primary hover:border-blue-500 transition-colors"
            >
              Try again
            </button>
          </div>

          <div className="p-4 space-y-3">
            <p className="text-primary text-xs font-mono break-all">
              {String(error?.message || error)}
            </p>
            <p className="text-muted text-[11px]">
              The rest of the dashboard is unaffected — switch tabs to keep
              working. The API and the raw logs are independent of this view.
            </p>
            {info?.componentStack && (
              <details>
                <summary className="text-muted text-[10px] uppercase tracking-wider cursor-pointer">
                  Component stack
                </summary>
                <pre className="mt-2 text-[10px] text-muted bg-panel border border-border rounded p-3 overflow-auto max-h-64 leading-relaxed">
                  {info.componentStack.trim()}
                </pre>
              </details>
            )}
          </div>
        </div>
      </div>
    );
  }
}
