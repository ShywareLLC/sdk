import { createRequire } from 'module';
import { TelemetryInterface } from './interface.js';

const require = createRequire(import.meta.url);

/**
 * XRayInterface — thin wrapper over aws-xray-sdk-core.
 *
 * Use this when running on EC2 with the X-Ray daemon (current setup).
 * To migrate to OTel (CloudFront/Amplify/generic), swap for OtelTelemetryInterface
 * and set OTEL_EXPORTER_OTLP_ENDPOINT to an X-Ray ADOT collector — zero other changes.
 */
export class XRayTelemetryInterface extends TelemetryInterface {
  constructor({ serviceName = 'shyware' } = {}) {
    super();
    this._serviceName = serviceName;
    this._xray = null;
  }

  get name() { return 'xray'; }

  _sdk() {
    if (!this._xray) this._xray = require('aws-xray-sdk');
    return this._xray;
  }

  expressMiddleware() {
    const AWSXRay = this._sdk();
    // aws-xray-sdk-core omits .express; fall back to noop so the server starts.
    // Install the full `aws-xray-sdk` package to get express segment wrapping.
    if (!AWSXRay?.express) {
      return [(_req, _res, next) => next(), (_req, _res, next) => next()];
    }
    return [
      AWSXRay.express.openSegment(this._serviceName),
      AWSXRay.express.closeSegment(),
    ];
  }

  captureHttps(mod) { this._sdk().captureHTTPsGlobal(mod); }

  resolveSegment() {
    try { return this._sdk().resolveSegment(); } catch { return null; }
  }

  async trace(spanName, attributes = {}, fn) {
    const seg = this.resolveSegment();
    const sub = seg ? seg.addNewSubsegment(spanName) : null;
    if (sub) for (const [k, v] of Object.entries(attributes)) sub.addAnnotation(k, String(v));
    try {
      const result = await fn();
      if (sub) sub.close();
      return result;
    } catch (err) {
      if (sub) { sub.addError(err); sub.close(); }
      throw err;
    }
  }
}
