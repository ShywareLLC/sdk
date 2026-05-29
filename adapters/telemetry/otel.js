import { TelemetryInterface } from './interface.js';

/**
 * OtelInterface — OpenTelemetry traces via OTLP.
 *
 * Works with any OTLP-compatible backend:
 *   AWS X-Ray        → set OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317  (X-Ray ADOT collector)
 *   AWS CloudWatch   → set OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317  (CloudWatch agent)
 *   Amplify/AppSync  → same OTLP collector, different exporter config
 *   Datadog / Jaeger → set OTEL_EXPORTER_OTLP_ENDPOINT to their collector
 *
 * Required peer dep in consumer: @opentelemetry/sdk-node @opentelemetry/auto-instrumentations-node
 *
 * Switching from X-Ray to CloudFront/Amplify observability = change OTEL_EXPORTER_OTLP_ENDPOINT.
 * Zero code changes in your consumer server.
 */
export class OtelTelemetryInterface extends TelemetryInterface {
  constructor({
    serviceName = process.env.OTEL_SERVICE_NAME || 'shyware',
    endpoint    = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4317',
  } = {}) {
    super();
    this._serviceName = serviceName;
    this._endpoint    = endpoint;
    this._tracer      = null;
    this._sdk         = null;
  }

  get name() { return `otel:${this._endpoint}`; }

  async _init() {
    if (this._tracer) return;
    const { NodeSDK }                      = await import('@opentelemetry/sdk-node');
    const { OTLPTraceExporter }            = await import('@opentelemetry/exporter-trace-otlp-grpc');
    const { Resource }                     = await import('@opentelemetry/resources');
    const { SEMRESATTRS_SERVICE_NAME }     = await import('@opentelemetry/semantic-conventions');
    const { trace }                        = await import('@opentelemetry/api');

    this._sdk = new NodeSDK({
      resource: new Resource({ [SEMRESATTRS_SERVICE_NAME]: this._serviceName }),
      traceExporter: new OTLPTraceExporter({ url: this._endpoint }),
      instrumentations: [],
    });
    this._sdk.start();
    this._tracer = trace.getTracer(this._serviceName);
  }

  expressMiddleware() {
    // OTel auto-instruments express; these are identity middleware.
    return [(_req, _res, next) => next(), (_req, _res, next) => next()];
  }

  async trace(spanName, attributes = {}, fn) {
    await this._init();
    const span = this._tracer.startSpan(spanName);
    for (const [k, v] of Object.entries(attributes)) span.setAttribute(k, v);
    try {
      const result = await fn();
      span.setStatus({ code: 1 /* OK */ });
      return result;
    } catch (err) {
      span.recordException(err);
      span.setStatus({ code: 2 /* ERROR */, message: err.message });
      throw err;
    } finally {
      span.end();
    }
  }
}
