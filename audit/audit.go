// Package audit provides structured audit logging for IAM operations.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event represents an IAM audit event.
type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	RequestID  string    `json:"request_id,omitempty"`
	UserID     string    `json:"user_id,omitempty"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Action     string    `json:"action"` // auth, permission_check, token_revoke, etc.
	Resource   string    `json:"resource,omitempty"`
	Result     string    `json:"result"` // success, failure, denied
	Details    string    `json:"details,omitempty"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Handler processes audit events. Implementations should not block.
type Handler func(event Event)

// Logger emits audit events to configured handlers.
type Logger struct {
	handlers []Handler
	queue    chan Event
	done     chan struct{}
	wg       sync.WaitGroup
}

// Option configures Logger behavior.
type Option func(*Logger)

// WithStdoutHandler adds a handler that writes JSON events to stdout.
func WithStdoutHandler() Option {
	return func(l *Logger) {
		l.AddHandler(func(e Event) {
			data, _ := json.Marshal(e)
			fmt.Fprintf(os.Stdout, "%s\n", data)
		})
	}
}

// WithHandler adds a custom event handler.
func WithHandler(h Handler) Option {
	return func(l *Logger) {
		l.AddHandler(h)
	}
}

// New creates a new audit logger with buffered async emission.
// bufferSize: event queue buffer size (default: 1000).
func New(bufferSize int, opts ...Option) *Logger {
	if bufferSize <= 0 {
		bufferSize = 1000
	}

	logger := &Logger{
		handlers: make([]Handler, 0),
		queue:    make(chan Event, bufferSize),
		done:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(logger)
	}

	// Start async event processor
	logger.wg.Add(1)
	go logger.process()

	return logger
}

// AddHandler adds a handler to receive audit events.
func (l *Logger) AddHandler(h Handler) {
	l.handlers = append(l.handlers, h)
}

// Log emits an audit event asynchronously.
func (l *Logger) Log(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case l.queue <- event:
	case <-l.done:
		// Logger is shutting down, event is dropped
	}
}

// process handles events from the queue.
func (l *Logger) process() {
	defer l.wg.Done()

	for {
		select {
		case event := <-l.queue:
			for _, h := range l.handlers {
				h(event)
			}
		case <-l.done:
			// Drain remaining events
			for {
				select {
				case event := <-l.queue:
					for _, h := range l.handlers {
						h(event)
					}
				default:
					return
				}
			}
		}
	}
}

// Close flushes pending events and stops the logger.
func (l *Logger) Close() error {
	close(l.done)
	l.wg.Wait()
	return nil
}

// FromContext retrieves the audit logger from context.
func FromContext(ctx context.Context) *Logger {
	logger, ok := ctx.Value(contextKeyLogger).(*Logger)
	if !ok {
		return nil
	}
	return logger
}

// WithContext stores the audit logger in context.
func WithContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, contextKeyLogger, logger)
}

// RequestID retrieves the request ID from context.
func RequestID(ctx context.Context) string {
	id, ok := ctx.Value(contextKeyRequestID).(string)
	if !ok {
		return ""
	}
	return id
}

// WithRequestID stores the request ID in context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKeyRequestID, id)
}

type contextKey string

const (
	contextKeyLogger    contextKey = "audit.logger"
	contextKeyRequestID contextKey = "audit.request_id"
)
