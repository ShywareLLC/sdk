/**
 * TelemetryInterface — provider-agnostic observability interface.
 *
 * Implementations: OtelInterface (OpenTelemetry → X-Ray / CloudWatch / Datadog),
 *                  XRayInterface (legacy aws-xray-sdk-core direct),
 *                  NoopInterface (dev / test).
 *
 * OTel is the recommended path: AWS X-Ray, CloudFront, and Amplify all
 * accept OTLP traces. Switching providers is an exporter config change,
 * not a code change.
 */
export class TelemetryInterface {
  get name() { throw new Error('TelemetryInterface.name not implemented'); }

  /** Instrument an Express app (open/close segment middleware). */
  expressMiddleware() { return [(_req, _res, next) => next(), (_req, _res, next) => next()]; }

  /**
   * Wrap an async fn in a named span/subsegment.
   * @param {string} spanName
   * @param {Record<string,string>} attributes
   * @param {() => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async trace(_spanName, _attributes, fn) { return fn(); }

  /** Capture HTTP outbound calls on the given http/https module. */
  captureHttps(_httpModule) {}

  /** Resolve the current active segment/span (for adapter interop). */
  resolveSegment() { return null; }
}
