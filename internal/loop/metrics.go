package loop

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the loop's Prometheus series. Labels are closed enums;
// there are no task, namespace, object or connector names as labels.
type Metrics struct {
	claims     *prometheus.CounterVec
	results    *prometheus.CounterVec
	heartbeats *prometheus.CounterVec
	catalogs   *prometheus.CounterVec
	discovery  *prometheus.CounterVec
	fetches    *prometheus.CounterVec
	inFlight   prometheus.Gauge
}

// NewMetrics builds the series and registers them with reg. A nil reg
// leaves them unregistered (tests). A series already registered by an
// earlier boot in the same process is reused.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		claims: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sb_gateway_claims_total",
			Help: "Task claim calls by outcome (task, empty, throttled, unauthorized, error).",
		}, []string{"outcome"}),
		results: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sb_gateway_results_total",
			Help: "Evidence results by outcome (accepted, duplicate, superseded, lease_expired, task_closed, fenced, dropped_late, rejected, error).",
		}, []string{"outcome"}),
		heartbeats: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sb_gateway_heartbeats_total",
			Help: "Heartbeat calls by outcome (ok, unauthorized, error).",
		}, []string{"outcome"}),
		catalogs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sb_gateway_catalog_uploads_total",
			Help: "Catalog uploads by outcome (ok, error).",
		}, []string{"outcome"}),
		discovery: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sb_gateway_discovery_runs_total",
			Help: "Discovery runs by outcome (accepted, duplicate, catalog_too_large, lease_not_held, discovery_generation_stale, scope_digest_mismatch, schema_violation, connector_not_found, invalid_request, over_privileged, abandoned, error).",
		}, []string{"outcome"}),
		fetches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sb_gateway_snapshot_fetches_total",
			Help: "Discovery snapshot fetches by outcome (opened, not_found, refused, error).",
		}, []string{"outcome"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sb_gateway_tasks_inflight",
			Help: "Observation passes in flight on this replica.",
		}),
	}
	if reg != nil {
		m.claims = register(reg, m.claims)
		m.results = register(reg, m.results)
		m.heartbeats = register(reg, m.heartbeats)
		m.catalogs = register(reg, m.catalogs)
		m.discovery = register(reg, m.discovery)
		m.fetches = register(reg, m.fetches)
		m.inFlight = register(reg, m.inFlight)
	}
	return m
}

func register[C prometheus.Collector](reg prometheus.Registerer, c C) C {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(C); ok {
				return existing
			}
		}
	}
	return c
}

func (m *Metrics) claim(outcome string)        { m.claims.WithLabelValues(outcome).Inc() }
func (m *Metrics) result(outcome string)       { m.results.WithLabelValues(outcome).Inc() }
func (m *Metrics) heartbeat(outcome string)    { m.heartbeats.WithLabelValues(outcome).Inc() }
func (m *Metrics) catalog(outcome string)      { m.catalogs.WithLabelValues(outcome).Inc() }
func (m *Metrics) discoveryRun(outcome string) { m.discovery.WithLabelValues(outcome).Inc() }
func (m *Metrics) fetch(outcome string)        { m.fetches.WithLabelValues(outcome).Inc() }
