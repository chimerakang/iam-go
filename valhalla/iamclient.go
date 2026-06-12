// One-line iam.Client assembly for Valhalla IAM servers.
//
// Instead of manually constructing 5-7 services and injecting them one by one,
// use New to get a fully wired *iam.Client:
//
//	client, err := valhalla.New("iam.example.com:50051")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Optional: M2M auth + tuning
//	client, err := valhalla.New("iam.example.com:50051",
//	    valhalla.WithOAuth2(os.Getenv("IAM_CLIENT_ID"), os.Getenv("IAM_CLIENT_SECRET")),
//	    valhalla.WithCacheTTL(time.Minute),
//	)
package valhalla

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/authz"
	"github.com/chimerakang/iam-go/jwks"
	"github.com/chimerakang/iam-go/oauth2"
	iamv1 "github.com/chimerakang/iam-go/proto/iam/v1"
	"google.golang.org/grpc"
)

// DefaultOAuth2Scopes are the scopes requested for M2M tokens when none are specified.
var DefaultOAuth2Scopes = []string{"iam:introspect", "iam:check-permission"}

// ClientOption configures New.
type ClientOption func(*clientConfig)

type clientConfig struct {
	grpcOpts  []grpc.DialOption
	jwksURL   string
	jwksOpts  []jwks.Option
	clientID  string
	exchanger iam.OAuth2TokenExchanger
	cacheTTL  time.Duration
	logger    *slog.Logger
}

// WithGRPCDialOptions sets gRPC dial options for the Valhalla connection.
// Default: insecure transport (development).
func WithGRPCDialOptions(opts ...grpc.DialOption) ClientOption {
	return func(c *clientConfig) { c.grpcOpts = opts }
}

// WithJWKSURL overrides the JWKS endpoint URL.
// Default: "http://<endpoint>/.well-known/jwks.json".
func WithJWKSURL(url string) ClientOption {
	return func(c *clientConfig) { c.jwksURL = url }
}

// WithJWKSOptions passes options to the underlying jwks.Verifier
// (e.g. jwks.WithLeeway, jwks.WithRefreshInterval, jwks.WithHTTPClient).
func WithJWKSOptions(opts ...jwks.Option) ClientOption {
	return func(c *clientConfig) { c.jwksOpts = append(c.jwksOpts, opts...) }
}

// WithClientID sets the OAuth2 Application client_id auto-injected into
// AuthService Login / SocialLogin requests.
func WithClientID(clientID string) ClientOption {
	return func(c *clientConfig) { c.clientID = clientID }
}

// WithOAuth2 enables M2M authentication via OAuth2 Client Credentials.
// The token URL defaults to "http://<endpoint>/api/v1/oauth/token"; override
// with WithOAuth2Exchanger(NewOAuth2Exchanger(id, secret, customURL)).
// Tokens are cached and refreshed automatically before expiry.
func WithOAuth2(clientID, clientSecret string, opts ...oauth2.Option) ClientOption {
	return func(c *clientConfig) {
		// Token URL is resolved against the endpoint inside New.
		c.exchanger = &deferredExchanger{clientID: clientID, clientSecret: clientSecret, opts: opts}
	}
}

// WithOAuth2Exchanger injects a pre-built OAuth2 token exchanger
// (e.g. from NewOAuth2Exchanger with a custom token URL).
func WithOAuth2Exchanger(e iam.OAuth2TokenExchanger) ClientOption {
	return func(c *clientConfig) { c.exchanger = e }
}

// WithCacheTTL sets how long permission decisions are cached locally.
// Default: iam.DefaultCacheTTL (5 minutes). Pass 0 to disable caching and
// hit the Valhalla AuthzService on every check.
func WithCacheTTL(ttl time.Duration) ClientOption {
	return func(c *clientConfig) { c.cacheTTL = ttl }
}

// WithLogger sets a structured logger on the assembled iam.Client.
func WithLogger(l *slog.Logger) ClientOption {
	return func(c *clientConfig) { c.logger = l }
}

// deferredExchanger marks that WithOAuth2 was used; the real exchanger is
// built in New once the endpoint-derived token URL is known.
type deferredExchanger struct {
	clientID     string
	clientSecret string
	opts         []oauth2.Option
}

func (d *deferredExchanger) ExchangeToken(context.Context, []string) (*iam.OAuth2Token, error) {
	return nil, fmt.Errorf("valhalla: exchanger not initialized")
}
func (d *deferredExchanger) GetCachedToken(context.Context) (string, error) {
	return "", fmt.Errorf("valhalla: exchanger not initialized")
}

// New connects to a Valhalla IAM server and returns a fully-assembled
// *iam.Client: JWKS verifier (RS256, 30s leeway), cached Authorizer, User /
// Tenant / Session / Auth services, and optionally an OAuth2 M2M exchanger.
//
// client.Close() closes the underlying gRPC connection.
func New(endpoint string, opts ...ClientOption) (*iam.Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("valhalla: endpoint is required")
	}

	cfg := &clientConfig{
		jwksURL:  fmt.Sprintf("http://%s/.well-known/jwks.json", endpoint),
		cacheTTL: iam.DefaultCacheTTL,
	}
	for _, o := range opts {
		o(cfg)
	}

	vc, err := NewClient(endpoint, cfg.grpcOpts...)
	if err != nil {
		return nil, err
	}
	if cfg.clientID != "" {
		vc.SetClientID(cfg.clientID)
	}

	// Standard JWKS verifier (RS256 + configurable leeway) instead of the
	// adapter's internal one.
	verifier := jwks.NewVerifier(cfg.jwksURL, cfg.jwksOpts...)

	// Authorizer: cached wrapper over the Valhalla AuthzService by default.
	authorizer := vc.Authz()
	if cfg.cacheTTL > 0 {
		authorizer = authz.New(
			&grpcAuthzBackend{client: vc.authzClient},
			authz.WithCacheTTL(cfg.cacheTTL),
		)
	}

	// Resolve a deferred WithOAuth2 exchanger now that the endpoint is known.
	exchanger := cfg.exchanger
	if d, ok := exchanger.(*deferredExchanger); ok {
		tokenURL := fmt.Sprintf("http://%s/api/v1/oauth/token", endpoint)
		exchanger = NewOAuth2Exchanger(d.clientID, d.clientSecret, tokenURL, d.opts...)
	}

	iamOpts := []iam.Option{
		iam.WithTokenVerifier(verifier),
		iam.WithAuthorizer(authorizer),
		iam.WithUserService(vc.Users()),
		iam.WithTenantService(vc.Tenants()),
		// Wrapped so iam.Client.Close() closes the gRPC connection.
		iam.WithSessionService(&closingSessionService{SessionService: vc.Sessions(), vc: vc}),
		iam.WithAuthService(vc.Auth()),
	}
	if exchanger != nil {
		iamOpts = append(iamOpts, iam.WithOAuth2Exchanger(exchanger))
	}
	if cfg.logger != nil {
		iamOpts = append(iamOpts, iam.WithLogger(cfg.logger))
	}

	return iam.NewClient(iam.Config{
		Endpoint: endpoint,
		JWKSUrl:  cfg.jwksURL,
		CacheTTL: cfg.cacheTTL,
	}, iamOpts...)
}

// NewOAuth2Exchanger creates the official Valhalla OAuth2 Client Credentials
// token exchanger for M2M authentication. Tokens are cached and refreshed
// automatically before expiry (singleflight-deduplicated).
//
// Scopes default to DefaultOAuth2Scopes; tune behavior with oauth2.Option
// (e.g. oauth2.WithRefreshBuffer, oauth2.WithHTTPClient).
func NewOAuth2Exchanger(clientID, clientSecret, tokenURL string, opts ...oauth2.Option) *oauth2.Exchanger {
	return oauth2.New(clientID, clientSecret, tokenURL, DefaultOAuth2Scopes, opts...)
}

// grpcAuthzBackend adapts the Valhalla AuthzService to the authz.Backend
// interface so permission decisions can be cached locally.
type grpcAuthzBackend struct {
	client iamv1.AuthzServiceClient
}

func (b *grpcAuthzBackend) CheckPermission(ctx context.Context, userID, _ /* tenantID */, permission string) (bool, error) {
	resp, err := b.client.CheckPermission(ctx, &iamv1.CheckPermissionRequest{
		UserId:     userID,
		Permission: permission,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}
	return resp.Allowed, nil
}

func (b *grpcAuthzBackend) GetPermissions(ctx context.Context, userID, _ /* tenantID */ string) ([]string, error) {
	resp, err := b.client.GetPermissions(ctx, &iamv1.GetPermissionsRequest{
		UserId: userID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}
	return resp.Permissions, nil
}

// closingSessionService forwards SessionService calls and closes the
// underlying gRPC connection when the iam.Client is closed.
type closingSessionService struct {
	iam.SessionService
	vc *Client
}

func (s *closingSessionService) Close() error { return s.vc.Close() }
