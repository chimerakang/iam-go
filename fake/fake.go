// Package fake provides in-memory implementations of all iam interfaces for testing.
//
// Use fake.NewClient() in unit tests to avoid network calls and external dependencies.
package fake

import (
	"context"
	"fmt"
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
	secrets     map[string]*secretEntry    // apiKey → entry
	sessions    map[string][]*iam.Session  // userID → sessions
	nextID      int
}

type secretEntry struct {
	secret *iam.Secret
	apiSecret string
	userID    string
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

// WithAPIKey adds a fake API key/secret pair linked to a user.
func WithAPIKey(apiKey, apiSecret, userID string) Option {
	return func(s *state) {
		s.secrets[apiKey] = &secretEntry{
			secret: &iam.Secret{
				ID:          apiKey,
				APIKey:      apiKey,
				Description: "fake",
				CreatedAt:   time.Now(),
			},
			apiSecret: apiSecret,
			userID:    userID,
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
		secrets:     make(map[string]*secretEntry),
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
	sec := &fakeSecretService{s: s}

	c, _ := iam.NewClient(
		iam.Config{Endpoint: "fake://localhost"},
		iam.WithTokenVerifier(v),
		iam.WithAuthorizer(a),
		iam.WithUserService(u),
		iam.WithTenantService(t),
		iam.WithSessionService(ss),
		iam.WithSecretService(sec),
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

// --- SecretService ---

type fakeSecretService struct{ s *state }

func (f *fakeSecretService) Create(_ context.Context, description string) (*iam.Secret, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	f.s.nextID++
	id := fmt.Sprintf("secret-%d", f.s.nextID)
	secret := &iam.Secret{
		ID:          id,
		APIKey:      fmt.Sprintf("ak_%d", f.s.nextID),
		APISecret:   fmt.Sprintf("sk_%d", f.s.nextID),
		Description: description,
		CreatedAt:   time.Now(),
	}
	f.s.secrets[secret.APIKey] = &secretEntry{
		secret:    secret,
		apiSecret: secret.APISecret,
	}
	return secret, nil
}

func (f *fakeSecretService) List(_ context.Context) ([]iam.Secret, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	result := make([]iam.Secret, 0, len(f.s.secrets))
	for _, e := range f.s.secrets {
		s := *e.secret
		s.APISecret = "" // Don't expose secrets on list
		result = append(result, s)
	}
	return result, nil
}

func (f *fakeSecretService) Delete(_ context.Context, secretID string) error {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	for key, e := range f.s.secrets {
		if e.secret.ID == secretID {
			delete(f.s.secrets, key)
			return nil
		}
	}
	return fmt.Errorf("iam/fake: secret %q not found", secretID)
}

func (f *fakeSecretService) Verify(_ context.Context, apiKey, apiSecret string) (*iam.Claims, error) {
	f.s.mu.RLock()
	defer f.s.mu.RUnlock()

	entry, ok := f.s.secrets[apiKey]
	if !ok || entry.apiSecret != apiSecret {
		return nil, fmt.Errorf("iam/fake: invalid API key/secret")
	}
	return &iam.Claims{
		Subject: entry.userID,
		Issuer:  "fake",
	}, nil
}

func (f *fakeSecretService) Rotate(_ context.Context, secretID string) (*iam.Secret, error) {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()

	for _, e := range f.s.secrets {
		if e.secret.ID == secretID {
			f.s.nextID++
			newSecret := fmt.Sprintf("sk_%d", f.s.nextID)
			e.apiSecret = newSecret
			result := *e.secret
			result.APISecret = newSecret
			return &result, nil
		}
	}
	return nil, fmt.Errorf("iam/fake: secret %q not found", secretID)
}

// --- context key for user ID ---

type ctxKey string

const userIDKey ctxKey = "iam_user_id"

// ContextWithUserID returns a context with the user ID set.
// Use this in tests to simulate an authenticated user.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

func userIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey).(string)
	return v
}
