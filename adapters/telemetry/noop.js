import { TelemetryInterface } from './interface.js';

/** NoopInterface — zero overhead, no external deps. Use in dev/test or when telemetry is disabled. */
export class NoopTelemetryInterface extends TelemetryInterface {
  get name() { return 'noop'; }
  async trace(_name, _attrs, fn) { return fn(); }
}
