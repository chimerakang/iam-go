package grpcmw

import (
	"context"
	"testing"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAuthenticate_Success(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	// Create context with authorization metadata
	md := metadata.Pairs("authorization", "Bearer user123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Call authenticate helper
	newCtx, err := authenticate(ctx, client)

	if err != nil {
		t.Fatalf("authenticate returned error: %v", err)
	}

	// Verify context was enriched
	if userID := iam.UserIDFromContext(newCtx); userID != "user123" {
		t.Errorf("expected userID user123, got %s", userID)
	}
	if tenantID := iam.TenantIDFromContext(newCtx); tenantID != "tenant123" {
		t.Errorf("expected tenantID tenant123, got %s", tenantID)
	}
}

func TestAuthenticate_MissingToken(t *testing.T) {
	client := fake.NewClient()

	// Create context without authorization metadata
	md := metadata.New(map[string]string{})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := authenticate(ctx, client)

	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", status.Code(err))
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	// Create context with invalid token
	md := metadata.Pairs("authorization", "Bearer unknown-user")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := authenticate(ctx, client)

	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", status.Code(err))
	}
}

func TestAuthenticateMultipleCases(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *iam.Client
		authHeader  string
		expectErr   bool
		expectCode  codes.Code
		expectUser  string
	}{
		{
			name: "valid token",
			setupClient: func() *iam.Client {
				return fake.NewClient(
					fake.WithUser("alice", "tenant1", "alice@example.com", []string{"user"}),
				)
			},
			authHeader: "Bearer alice",
			expectErr:  false,
			expectUser: "alice",
		},
		{
			name: "empty token",
			setupClient: func() *iam.Client {
				return fake.NewClient()
			},
			authHeader: "",
			expectErr:  true,
			expectCode: codes.Unauthenticated,
		},
		{
			name: "malformed bearer",
			setupClient: func() *iam.Client {
				return fake.NewClient()
			},
			authHeader: "NotBearer token",
			expectErr:  true,
			expectCode: codes.Unauthenticated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.setupClient()
			var md metadata.MD
			if tc.authHeader != "" {
				md = metadata.Pairs("authorization", tc.authHeader)
			} else {
				md = metadata.New(map[string]string{})
			}
			ctx := metadata.NewIncomingContext(context.Background(), md)

			newCtx, err := authenticate(ctx, client)

			if tc.expectErr {
				if err == nil {
					t.Errorf("%s: expected error but got none", tc.name)
				}
				if status.Code(err) != tc.expectCode {
					t.Errorf("%s: expected code %v, got %v", tc.name, tc.expectCode, status.Code(err))
				}
			} else {
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tc.name, err)
				}
				if userID := iam.UserIDFromContext(newCtx); userID != tc.expectUser {
					t.Errorf("%s: expected user %s, got %s", tc.name, tc.expectUser, userID)
				}
			}
		})
	}
}

func TestExtractBearerFromMD_Success(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer mytoken123")
	token := extractBearerFromMD(md)

	if token != "mytoken123" {
		t.Errorf("expected mytoken123, got %s", token)
	}
}

func TestExtractBearerFromMD_Empty(t *testing.T) {
	md := metadata.New(map[string]string{})
	token := extractBearerFromMD(md)

	if token != "" {
		t.Errorf("expected empty string, got %s", token)
	}
}

func TestExtractBearerFromMD_NoBearer(t *testing.T) {
	md := metadata.Pairs("authorization", "Basic credentials")
	token := extractBearerFromMD(md)

	if token != "" {
		t.Errorf("expected empty string for non-Bearer, got %s", token)
	}
}

func TestWrappedStream_Context(t *testing.T) {
	// Create a wrapped stream with a custom context
	customCtx := context.WithValue(context.Background(), "key", "value")

	// Create a mock stream with different context
	mockStream := &mockServerStream{ctx: context.Background()}
	wrapped := &wrappedStream{ServerStream: mockStream, ctx: customCtx}

	// Verify wrapped stream returns custom context
	if wrapped.Context() != customCtx {
		t.Error("wrapped stream should return custom context")
	}
}

type mockServerStream struct {
	ctx context.Context
}

func (m *mockServerStream) SetHeader(metadata.MD) error   { return nil }
func (m *mockServerStream) SendHeader(metadata.MD) error  { return nil }
func (m *mockServerStream) SetTrailer(metadata.MD)        {}
func (m *mockServerStream) Context() context.Context      { return m.ctx }
func (m *mockServerStream) SendMsg(interface{}) error     { return nil }
func (m *mockServerStream) RecvMsg(interface{}) error     { return nil }
