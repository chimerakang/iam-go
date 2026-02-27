// Package fake provides in-memory implementations of all iam interfaces for testing.
//
// Use fake.NewClient() in unit tests to avoid network calls and external dependencies.
package fake

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	iam "github.com/chimerakang/iam-go"
)

// Option configures the fake client.
type Option func(*state)

type state struct {
	mu          sync.RWMutex
	users       map[string]*iam.User       // userID → User
	tenants     map[string]*iam.Tenant     // tenantID → Tenant
	tenantSlugs map[string]string          // slug → tenantID
	permissions map[string]map[string]bool // userID → permission → allowed
	sessions    map[string][]*iam.Session  // userID → sessions
	oauth2App   *oauth2AppEntry            // OAuth2 application credentials
}

type oauth2AppEntry struct {
	clientID     string
	clientSecret string
	scopes       []string
}

// WithUser adds a fake user.
func WithUser(id, tenantID, email string, roleNames []string) Option {
	return func(s *state) {
		roles := make([]iam.Role, len(roleNames))
		for i, name := range roleNames {
			roles[i] = iam.Role{ID: name, Name: name}
		}
		s.users[id] = &iam.User{
			ID:       id,
			Email:    email,
			Name:     email,
			TenantID: tenantID,
			Roles:    roles,
		}
	}
}

// WithTenant adds a fake tenant.
func WithTenant(id, slug, status string) Option {
	return func(s *state) {
		s.tenants[id] = &iam.Tenant{
			ID:     id,
			Name:   slug,
			Slug:   slug,
			Status: status,
		}
		s.tenantSlugs[slug] = id
	}
}

// WithPermissions sets the allowed permissions for a user.
func WithPermissions(userID string, perms []string) Option {
	return func(s *state) {
		m := make(map[string]bool, len(perms))
		for _, p := range perms {
			m[p] = true
		}
		s.permissions[userID] = m
	}
}

// WithOAuth2App configures a fake OAuth2 application for client credentials testing.
func WithOAuth2App(clientID, clientSecret string, scopes []string) Option {
	return func(s *state) {
		s.oauth2App = &oauth2AppEntry{
			clientID:     clientID,
			clientSecret: clientSecret,
			scopes:       scopes,
		}
	}
}

// NewClient creates an *iam.Client with all services wired to in-memory fakes.
func NewClient(opts ...Option) *iam.Client {
	s := &state{
		users:       make(map[string]*iam.User),
		tenants:     make(map[string]*iam.Tenant),
		tenantSlugs: make(map[string]string),
		permissions: make(map[string]map[string]bool),
		sessions:    make(map[string][]*iam.Session),
	}
	for _, o := range opts {
		o(s)
	}

	v := &fakeVerifier{s: s}
	a := &fakeAuthorizer{s: s}
	u := &fakeUserService{s: s}
	t := &fakeTenantService{s: s}
	ss := &fakeSessionService{s: s}

	clientOpts := []iam.Option{
		iam.WithTokenVerifier(v),
		iam.WithAuthorizer(a),
		iam.WithUserService(u),
		iam.WithTenantService(t),
		iam.WithSessionService(ss),
	}

	if s.oauth2App != nil {
		clientOpts = append(clientOpts, iam.WithOAuth2Exchanger(&fakeOAuth2Exchanger{s: s}))
	}

	c, _ := iam.NewClient(
		iam.Config{Endpoint: "fake://localhost"},
		clientOpts...,
	)
	return c
}

// --- TokenVerifier ---

type fakeVerifier struct{ s *state }

func (f *fakeVerifier) Verify(_ context.Context, token string) (*iam.Claims, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	// Treat the token string as a userID for simplicity
	user, ok := f.s.users[token]
	if !ok {
		return nil, fmt.Errorf("iam/fake: unknown token %q", token)
	}

	roleNames := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roleNames[i] = r.Name
	}

	return &iam.Claims{
		Subject:   user.ID,
		TenantID:  user.TenantID,
		Roles:     roleNames,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		Issuer:    "fake",
	}, nil
}

// --- Authorizer ---

type fakeAuthorizer struct{ s *state }

func (f *fakeAuthorizer) Check(ctx context.Context, permission string) (bool, error) {
	userID := userIDFromCtx(ctx)
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	perms, ok := f.s.permissions[userID]
	if !ok {
		return false, nil
	}
	return perms[permission], nil
}

func (f *fakeAuthorizer) CheckResource(ctx context.Context, resource, action string) (bool, error) {
	return f.Check(ctx, resource+":"+action)
}

func (f *fakeAuthorizer) GetPermissions(ctx context.Context) ([]string, error) {
	userID := userIDFromCtx(ctx)
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	perms, ok := f.s.permissions[userID]
	if !ok {
		return nil, nil
	}
	result := make([]string, 0, len(perms))
	for p := range perms {
		result = append(result, p)
	}
	return result, nil
}

// --- UserService ---

type fakeUserService struct{ s *state }

func (f *fakeUserService) GetCurrent(ctx context.Context) (*iam.User, error) {
	return f.Get(ctx, userIDFromCtx(ctx))
}

func (f *fakeUserService) Get(_ context.Context, userID string) (*iam.User, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	user, ok := f.s.users[userID]
	if !ok {
		return nil, fmt.Errorf("iam/fake: user %q not found", userID)
	}
	return user, nil
}

func (f *fakeUserService) List(_ context.Context, opts iam.ListOptions) ([]*iam.User, int, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	all := make([]*iam.User, 0, len(f.s.users))
	for _, u := range f.s.users {
		all = append(all, u)
	}

	total := len(all)
	page := opts.Page
	if page < 1 {
		page = 1
	}
	size := opts.PageSize
	if size < 1 {
		size = 20
	}

	start := (page - 1) * size
	if start >= total {
		return nil, total, nil
	}
	end := start + size
	if end > total {
		end = total
	}
	return all[start:end], total, nil
}

func (f *fakeUserService) GetRoles(_ context.Context, userID string) ([]iam.Role, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	user, ok := f.s.users[userID]
	if !ok {
		return nil, fmt.Errorf("iam/fake: user %q not found", userID)
	}
	return user.Roles, nil
}

// --- TenantService ---

type fakeTenantService struct{ s *state }

func (f *fakeTenantService) Resolve(_ context.Context, identifier string) (*iam.Tenant, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	// Try by ID first, then by slug
	if t, ok := f.s.tenants[identifier]; ok {
		return t, nil
	}
	if id, ok := f.s.tenantSlugs[identifier]; ok {
		return f.s.tenants[id], nil
	}
	return nil, fmt.Errorf("iam/fake: tenant %q not found", identifier)
}

func (f *fakeTenantService) ValidateMembership(_ context.Context, userID, tenantID string) (bool, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	user, ok := f.s.users[userID]
	if !ok {
		return false, nil
	}
	return user.TenantID == tenantID, nil
}

// --- SessionService ---

type fakeSessionService struct{ s *state }

func (f *fakeSessionService) List(ctx context.Context) ([]iam.Session, error) {
	userID := userIDFromCtx(ctx)
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	sessions := f.s.sessions[userID]
	result := make([]iam.Session, len(sessions))
	for i, s := range sessions {
		result[i] = *s
	}
	return result, nil
}

func (f *fakeSessionService) Revoke(_ context.Context, sessionID string) error {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	for uid, sessions := range f.s.sessions {
		for i, s := range sessions {
			if s.ID == sessionID {
				f.s.sessions[uid] = append(sessions[:i], sessions[i+1:]...)
				return nil
			}
		}
	}
	return fmt.Errorf("iam/fake: session %q not found", sessionID)
}

func (f *fakeSessionService) RevokeAllOthers(ctx context.Context) error {
	// No-op in fake: no concept of "current session"
	return nil
}

// --- OAuth2TokenExchanger ---

type fakeOAuth2Exchanger struct{ s *state }

func (f *fakeOAuth2Exchanger) ExchangeToken(_ context.Context, scopes []string) (*iam.OAuth2Token, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	if f.s.oauth2App == nil {
		return nil, fmt.Errorf("iam/fake: no oauth2 app configured")
	}

	return &iam.OAuth2Token{
		AccessToken: "fake_access_token_" + f.s.oauth2App.clientID,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func (f *fakeOAuth2Exchanger) GetCachedToken(ctx context.Context) (string, error) {
	token, err := f.ExchangeToken(ctx, nil)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// ContextWithUserID returns a context with the user ID set.
// Use this in tests to simulate an authenticated user.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return iam.WithUserID(ctx, userID)
}

func userIDFromCtx(ctx context.Context) string {
	return iam.UserIDFromContext(ctx)
}
