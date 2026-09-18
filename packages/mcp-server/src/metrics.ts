// In-process Prometheus text-format metrics registry for the Clockchain MCP
// HTTP surface. Deliberately dependency-free: the exposition format is a few
// lines to render and a new runtime dependency is not justified for it.
//
// Cardinality contract: every instrumented label is drawn from a bounded set
// (route class, tool name, result kind, stage allowlist, reason code, probe
// name, client class). Callers funnel values through `bounded()` so a surprise
// value collapses to "other" instead of minting a new series. Never pass
// session ids, role-access handles, keys, addresses, digests, statements, or
// raw error text into labels — they are unbounded AND sensitive.

export type MetricLabels = Record<string, string>;

const NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const LABEL_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

function escLabelValue(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/** Escape a HELP docstring for exposition (backslash + newline). */
function escHelp(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n");
}

function seriesKey(name: string, labels: MetricLabels): string {
  const parts = Object.keys(labels)
    .sort()
    .map((k) => {
      if (!LABEL_RE.test(k)) throw new Error(`bad label name ${k}`);
      return `${k}="${escLabelValue(labels[k])}"`;
    });
  return parts.length ? `${name}{${parts.join(",")}}` : name;
}

/** Collapse a value to an allowlist; unknown values become `fallback`. */
export function bounded(value: string | undefined | null, allowed: readonly string[], fallback = "other"): string {
  return value != null && allowed.includes(value) ? value : fallback;
}

interface Series {
  name: string;
  help: string;
  type: "counter" | "gauge" | "histogram";
}

class Counter implements Series {
  readonly type = "counter" as const;
  private values = new Map<string, number>();
  constructor(readonly name: string, readonly help: string) {}
  inc(labels: MetricLabels = {}, n = 1): void {
    const k = seriesKey(this.name, labels);
    this.values.set(k, (this.values.get(k) ?? 0) + n);
  }
  render(): string {
    return [...this.values.entries()].map(([k, v]) => `${k} ${v}`).join("\n");
  }
  /** Test/inspection hook: current value for a label set. */
  value(labels: MetricLabels = {}): number {
    return this.values.get(seriesKey(this.name, labels)) ?? 0;
  }
  /** Total across all series in this counter. */
  sum(): number {
    let total = 0;
    for (const v of this.values.values()) total += v;
    return total;
  }
}

class Gauge implements Series {
  readonly type = "gauge" as const;
  private values = new Map<string, number>();
  constructor(readonly name: string, readonly help: string) {}
  set(labels: MetricLabels, v: number): void {
    this.values.set(seriesKey(this.name, labels), v);
  }
  inc(labels: MetricLabels = {}, n = 1): void {
    const k = seriesKey(this.name, labels);
    this.values.set(k, (this.values.get(k) ?? 0) + n);
  }
  dec(labels: MetricLabels = {}, n = 1): void {
    this.inc(labels, -n);
  }
  render(): string {
    return [...this.values.entries()].map(([k, v]) => `${k} ${v}`).join("\n");
  }
  value(labels: MetricLabels = {}): number {
    return this.values.get(seriesKey(this.name, labels)) ?? 0;
  }
}

class Histogram implements Series {
  readonly type = "histogram" as const;
  private buckets: number[];
  private counts = new Map<string, number[]>(); // seriesKey-without-le -> per-bucket counts
  private sums = new Map<string, number>();
  private totals = new Map<string, number>();
  private labelSets = new Map<string, MetricLabels>();
  constructor(readonly name: string, readonly help: string, buckets: readonly number[]) {
    this.buckets = [...buckets].sort((a, b) => a - b);
  }
  observe(labels: MetricLabels, v: number): void {
    const k = seriesKey(this.name, labels);
    let c = this.counts.get(k);
    if (!c) {
      c = this.buckets.map(() => 0);
      this.counts.set(k, c);
      this.labelSets.set(k, labels);
    }
    for (let i = 0; i < this.buckets.length; i++) {
      if (v <= this.buckets[i]) c[i] += 1;
    }
    this.sums.set(k, (this.sums.get(k) ?? 0) + v);
    this.totals.set(k, (this.totals.get(k) ?? 0) + 1);
  }
  render(): string {
    const lines: string[] = [];
    for (const [k, counts] of this.counts.entries()) {
      const labels = this.labelSets.get(k)!;
      for (let i = 0; i < this.buckets.length; i++) {
        const withLe = { ...labels, le: String(this.buckets[i]) };
        lines.push(`${seriesKey(`${this.name}_bucket`, withLe)} ${counts[i]}`);
      }
      lines.push(`${seriesKey(`${this.name}_bucket`, { ...labels, le: "+Inf" })} ${this.totals.get(k)}`);
      lines.push(`${seriesKey(`${this.name}_sum`, labels)} ${this.sums.get(k)}`);
      lines.push(`${seriesKey(`${this.name}_count`, labels)} ${this.totals.get(k)}`);
    }
    return lines.join("\n");
  }
  count(labels: MetricLabels = {}): number {
    return this.totals.get(seriesKey(this.name, labels)) ?? 0;
  }
  /**
   * Prometheus histogram_quantile for one label set: finds the first bucket
   * whose cumulative count reaches q*total and linearly interpolates within
   * it. Returns undefined when the series has no observations. Clamped to the
   * top finite bucket when the quantile lands in the +Inf gap.
   */
  quantile(labels: MetricLabels, q: number): number | undefined {
    const k = seriesKey(this.name, labels);
    const counts = this.counts.get(k);
    const total = this.totals.get(k) ?? 0;
    if (!counts || total === 0) return undefined;
    const rank = Math.min(Math.max(q, 0), 1) * total;
    let prevCount = 0;
    let prevBound = 0;
    for (let i = 0; i < this.buckets.length; i++) {
      const cumulative = counts[i];
      if (cumulative >= rank) {
        const upper = this.buckets[i];
        if (cumulative === prevCount) return upper;
        return prevBound + (upper - prevBound) * ((rank - prevCount) / (cumulative - prevCount));
      }
      prevCount = cumulative;
      prevBound = this.buckets[i];
    }
    return this.buckets[this.buckets.length - 1];
  }
}

export class MetricsRegistry {
  private series = new Map<string, Counter | Gauge | Histogram>();
  counter(name: string, help: string): Counter {
    const s = this.getOrCreate(name, help, "counter") as Counter;
    return s;
  }
  gauge(name: string, help: string): Gauge {
    return this.getOrCreate(name, help, "gauge") as Gauge;
  }
  histogram(name: string, help: string, buckets: readonly number[] = DEFAULT_BUCKETS): Histogram {
    if (!NAME_RE.test(name)) throw new Error(`bad metric name ${name}`);
    const existing = this.series.get(name);
    if (existing) {
      if (existing.type !== "histogram") throw new Error(`metric ${name} redeclared as histogram`);
      return existing as Histogram;
    }
    const created = new Histogram(name, help, buckets);
    this.series.set(name, created);
    return created;
  }
  private getOrCreate(name: string, help: string, type: Series["type"]): Counter | Gauge | Histogram {
    if (!NAME_RE.test(name)) throw new Error(`bad metric name ${name}`);
    const existing = this.series.get(name);
    if (existing) {
      if (existing.type !== type) throw new Error(`metric ${name} redeclared as ${type}`);
      return existing;
    }
    const created =
      type === "counter" ? new Counter(name, help)
      : type === "gauge" ? new Gauge(name, help)
      : new Histogram(name, help, DEFAULT_BUCKETS);
    this.series.set(name, created);
    return created;
  }
  /** Full Prometheus text exposition for GET /metrics. */
  collect(): string {
    const out: string[] = [];
    for (const s of this.series.values()) {
      out.push(`# HELP ${s.name} ${escHelp(s.help)}`);
      out.push(`# TYPE ${s.name} ${s.type}`);
      const body = s.render();
      if (body) out.push(body);
    }
    return out.join("\n") + "\n";
  }
  /** Names of all registered series (test hook for cardinality audits). */
  names(): string[] {
    return [...this.series.keys()];
  }
}

/** Default duration histogram buckets (seconds): sub-ms to 30s. */
export const DEFAULT_BUCKETS = Object.freeze([
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
]);
