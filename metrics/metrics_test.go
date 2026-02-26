package metrics

import (
	"testing"
)

// Global metrics instance (reused across enabled tests to avoid Prometheus registry conflicts)
var globalMetrics *Metrics

func init() {
	globalMetrics = New(true)
}

func TestMetricsEnabled(t *testing.T) {
	if globalMetrics == nil {
		t.Fatal("metrics should not be nil")
	}
}

func TestMetricsDisabled(t *testing.T) {
	metrics := New(false)

	if metrics == nil {
		t.Fatal("metrics should not be nil (noop)")
	}

	// These should not panic even though they're noop
	metrics.RecordAuthSuccess("jwt")
	metrics.RecordAuthFailure("apikey", "invalid")
	metrics.RecordPermissionCheck("allowed", 0.001)
	metrics.RecordCacheHit("authz")
	metrics.RecordCacheMiss("tenant")
	metrics.SetCacheSize("user", 42)
	metrics.SetConnectionState("grpc", true)
}

func TestRecordAuthSuccess(t *testing.T) {
	// Should not panic
	globalMetrics.RecordAuthSuccess("jwt")
	globalMetrics.RecordAuthSuccess("apikey")
}

func TestRecordAuthFailure(t *testing.T) {
	// Should not panic
	globalMetrics.RecordAuthFailure("jwt", "expired")
	globalMetrics.RecordAuthFailure("apikey", "invalid_secret")
}

func TestRecordPermissionCheck(t *testing.T) {
	// Should not panic
	globalMetrics.RecordPermissionCheck("allowed", 0.001)
	globalMetrics.RecordPermissionCheck("denied", 0.002)
}

func TestRecordCacheMetrics(t *testing.T) {
	// Should not panic
	globalMetrics.RecordCacheHit("authz")
	globalMetrics.RecordCacheHit("tenant")
	globalMetrics.RecordCacheMiss("user")
	globalMetrics.SetCacheSize("authz", 100)
	globalMetrics.SetCacheSize("tenant", 50)
}

func TestSetConnectionState(t *testing.T) {
	// Should not panic
	globalMetrics.SetConnectionState("iam-grpc", true)
	globalMetrics.SetConnectionState("iam-grpc", false)
	globalMetrics.SetConnectionState("auth-grpc", true)
}

func TestNoopMetrics(t *testing.T) {
	metrics := New(false)

	tests := []func(){
		func() { metrics.RecordAuthSuccess("jwt") },
		func() { metrics.RecordAuthFailure("jwt", "error") },
		func() { metrics.RecordPermissionCheck("allowed", 0.001) },
		func() { metrics.RecordCacheHit("authz") },
		func() { metrics.RecordCacheMiss("authz") },
		func() { metrics.SetCacheSize("authz", 10) },
		func() { metrics.SetConnectionState("service", true) },
	}

	for _, test := range tests {
		test() // Should not panic
	}
}

func TestMultipleCacheTypes(t *testing.T) {
	// Test different cache types
	cacheTypes := []string{"authz", "tenant", "user", "session", "secret"}

	for _, cacheType := range cacheTypes {
		globalMetrics.RecordCacheHit(cacheType)
		globalMetrics.RecordCacheMiss(cacheType)
		globalMetrics.SetCacheSize(cacheType, float64(len(cacheType)))
	}
}

func TestMultipleServices(t *testing.T) {
	services := []string{"iam-grpc", "auth-grpc", "user-grpc"}

	for _, service := range services {
		globalMetrics.SetConnectionState(service, true)
		globalMetrics.SetConnectionState(service, false)
	}
}
