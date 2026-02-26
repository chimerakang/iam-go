// Package metrics provides Prometheus metrics for IAM operations.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for IAM operations.
type Metrics struct {
	enabled bool

	// Authentication metrics
	authRequestsTotal  prometheus.Counter
	authFailuresTotal  *prometheus.CounterVec

	// Permission check metrics
	permissionChecksTotal     *prometheus.CounterVec
	permissionCheckDuration   prometheus.Histogram

	// Cache metrics
	cacheEntriesTotal *prometheus.GaugeVec
	cacheHitsTotal    *prometheus.CounterVec
	cacheMissTotal    *prometheus.CounterVec

	// Connection metrics
	grpcConnectionState *prometheus.GaugeVec
}

// New creates and registers Prometheus metrics.
// If enabled is false, returns a no-op Metrics instance.
func New(enabled bool) *Metrics {
	m := &Metrics{enabled: enabled}

	if !enabled {
		return m
	}

	// Authentication metrics
	m.authRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "iam_auth_requests_total",
		Help: "Total authentication requests",
	})

	m.authFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_auth_failures_total",
		Help: "Total authentication failures",
	}, []string{"method", "reason"})

	// Permission check metrics
	m.permissionChecksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_permission_checks_total",
		Help: "Total permission checks",
	}, []string{"result"})

	m.permissionCheckDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "iam_permission_check_duration_seconds",
		Help:    "Permission check duration in seconds",
		Buckets: prometheus.DefBuckets,
	})

	// Cache metrics
	m.cacheEntriesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "iam_cache_entries",
		Help: "Current number of entries in cache",
	}, []string{"cache_type"})

	m.cacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_cache_hits_total",
		Help: "Total cache hits",
	}, []string{"cache_type"})

	m.cacheMissTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "iam_cache_misses_total",
		Help: "Total cache misses",
	}, []string{"cache_type"})

	// Connection metrics
	m.grpcConnectionState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "iam_grpc_connection_state",
		Help: "gRPC connection state (0=disconnected, 1=connected)",
	}, []string{"service"})

	return m
}

// RecordAuthSuccess records a successful authentication.
func (m *Metrics) RecordAuthSuccess(method string) {
	if !m.enabled {
		return
	}
	m.authRequestsTotal.Inc()
}

// RecordAuthFailure records a failed authentication.
func (m *Metrics) RecordAuthFailure(method, reason string) {
	if !m.enabled {
		return
	}
	m.authFailuresTotal.WithLabelValues(method, reason).Inc()
}

// RecordPermissionCheck records a permission check result.
func (m *Metrics) RecordPermissionCheck(result string, durationSeconds float64) {
	if !m.enabled {
		return
	}
	m.permissionChecksTotal.WithLabelValues(result).Inc()
	m.permissionCheckDuration.Observe(durationSeconds)
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit(cacheType string) {
	if !m.enabled {
		return
	}
	m.cacheHitsTotal.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss(cacheType string) {
	if !m.enabled {
		return
	}
	m.cacheMissTotal.WithLabelValues(cacheType).Inc()
}

// SetCacheSize sets the current cache size.
func (m *Metrics) SetCacheSize(cacheType string, size float64) {
	if !m.enabled {
		return
	}
	m.cacheEntriesTotal.WithLabelValues(cacheType).Set(size)
}

// SetConnectionState sets the connection state (0=disconnected, 1=connected).
func (m *Metrics) SetConnectionState(service string, connected bool) {
	if !m.enabled {
		return
	}
	state := 0.0
	if connected {
		state = 1.0
	}
	m.grpcConnectionState.WithLabelValues(service).Set(state)
}
