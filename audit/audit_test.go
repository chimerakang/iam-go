package audit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestEventEmission(t *testing.T) {
	var mu sync.Mutex
	var events []Event

	logger := New(10, WithHandler(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}))
	defer logger.Close()

	event := Event{
		Action:   "auth",
		Result:   "success",
		UserID:   "user123",
		TenantID: "tenant456",
	}
	logger.Log(event)

	// Give async processor time to handle event
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].UserID != "user123" {
		t.Errorf("expected user123, got %s", events[0].UserID)
	}
	if events[0].Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
}

func TestMultipleHandlers(t *testing.T) {
	var mu1, mu2 sync.Mutex
	var events1, events2 []Event

	handler1 := func(e Event) {
		mu1.Lock()
		defer mu1.Unlock()
		events1 = append(events1, e)
	}

	handler2 := func(e Event) {
		mu2.Lock()
		defer mu2.Unlock()
		events2 = append(events2, e)
	}

	logger := New(10, WithHandler(handler1), WithHandler(handler2))
	defer logger.Close()

	event := Event{Action: "test", Result: "success"}
	logger.Log(event)

	time.Sleep(100 * time.Millisecond)

	mu1.Lock()
	if len(events1) != 1 {
		t.Fatalf("handler1: expected 1 event, got %d", len(events1))
	}
	mu1.Unlock()

	mu2.Lock()
	if len(events2) != 1 {
		t.Fatalf("handler2: expected 1 event, got %d", len(events2))
	}
	mu2.Unlock()
}

func TestContextStorage(t *testing.T) {
	logger := New(10)
	defer logger.Close()

	ctx := context.Background()
	ctx = WithContext(ctx, logger)
	ctx = WithRequestID(ctx, "req-12345")

	retrieved := FromContext(ctx)
	if retrieved == nil {
		t.Fatal("logger not found in context")
	}

	requestID := RequestID(ctx)
	if requestID != "req-12345" {
		t.Errorf("expected req-12345, got %s", requestID)
	}
}

func TestEventTimestamp(t *testing.T) {
	var mu sync.Mutex
	var events []Event

	logger := New(10, WithHandler(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}))
	defer logger.Close()

	now := time.Now()
	event := Event{Action: "test", Result: "success"}
	logger.Log(event)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if events[0].Timestamp.Before(now) || events[0].Timestamp.After(now.Add(1*time.Second)) {
		t.Error("timestamp not properly set")
	}
}

func TestQueueBuffer(t *testing.T) {
	var mu sync.Mutex
	var count int

	logger := New(5, WithHandler(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		count++
		time.Sleep(50 * time.Millisecond) // Simulate slow handler
	}))
	defer logger.Close()

	// Emit 5 events (fill buffer)
	for i := 0; i < 5; i++ {
		event := Event{Action: "test", Result: "success"}
		logger.Log(event)
	}

	// Events should be queued without blocking
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	if count != 5 {
		t.Errorf("expected 5 events processed, got %d", count)
	}
	mu.Unlock()
}

func TestErrorEvent(t *testing.T) {
	var mu sync.Mutex
	var events []Event

	logger := New(10, WithHandler(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}))
	defer logger.Close()

	event := Event{
		Action: "auth",
		Result: "failure",
		Error:  "invalid token",
		UserID: "unknown",
	}
	logger.Log(event)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Error != "invalid token" {
		t.Errorf("expected 'invalid token', got %s", events[0].Error)
	}
	if events[0].Result != "failure" {
		t.Errorf("expected 'failure', got %s", events[0].Result)
	}
}

func TestAuditEventFields(t *testing.T) {
	var mu sync.Mutex
	var events []Event

	logger := New(10, WithHandler(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}))
	defer logger.Close()

	event := Event{
		UserID:    "user123",
		TenantID:  "tenant456",
		Action:    "permission_check",
		Resource:  "users:read",
		Result:    "denied",
		Details:   "insufficient permissions",
		IP:        "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}
	logger.Log(event)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.UserID != "user123" || e.TenantID != "tenant456" ||
	   e.Action != "permission_check" || e.Resource != "users:read" ||
	   e.Result != "denied" || e.IP != "192.168.1.1" {
		t.Error("audit event fields not correctly set")
	}
}
