-- PostgreSQL initialization script for iam-go integration tests
-- This script sets up the database schema for testing IAM functionality

-- Create tables for users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for tenants
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create table for roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, name)
);

-- Create table for permissions
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource VARCHAR(255),
    action VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, name)
);

-- Create table for role permissions
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Create table for user tenants (multi-tenancy)
CREATE TABLE IF NOT EXISTS user_tenants (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    status VARCHAR(20) DEFAULT 'active',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, tenant_id)
);

-- Create table for user roles
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, tenant_id, role_id)
);

-- Create table for API secrets
CREATE TABLE IF NOT EXISTS api_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    secret_id VARCHAR(32) UNIQUE NOT NULL,      -- public API Key
    secret_key_hash VARCHAR(255) NOT NULL,      -- bcrypt hash
    description TEXT,
    status VARCHAR(20) DEFAULT 'active',
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (user_id, tenant_id),
    INDEX (secret_id)
);

-- Create table for sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'active',
    expires_at TIMESTAMP,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (user_id, tenant_id),
    INDEX (status, expires_at)
);

-- Create table for audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id VARCHAR(255),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    action VARCHAR(255),
    resource VARCHAR(255),
    result VARCHAR(20),      -- success, failure
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (user_id, tenant_id),
    INDEX (action, result),
    INDEX (created_at)
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_roles_tenant ON roles(tenant_id);
CREATE INDEX idx_permissions_tenant ON permissions(tenant_id);
CREATE INDEX idx_user_tenants_user ON user_tenants(user_id);
CREATE INDEX idx_user_tenants_tenant ON user_tenants(tenant_id);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_tenant ON user_roles(tenant_id);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_tenant ON sessions(tenant_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(created_at DESC);

-- Insert test data
INSERT INTO tenants (id, name, slug, status) VALUES
    ('550e8400-e29b-41d4-a716-446655440001'::uuid, 'Acme Corp', 'acme-corp', 'active'),
    ('550e8400-e29b-41d4-a716-446655440002'::uuid, 'TechStart Inc', 'techstart', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO users (id, email, name, status) VALUES
    ('550e8400-e29b-41d4-a716-446655440101'::uuid, 'admin@acme.com', 'Admin User', 'active'),
    ('550e8400-e29b-41d4-a716-446655440102'::uuid, 'user@acme.com', 'Regular User', 'active'),
    ('550e8400-e29b-41d4-a716-446655440103'::uuid, 'service@techstart.com', 'Service Account', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, tenant_id, name, description, status) VALUES
    ('550e8400-e29b-41d4-a716-446655440201'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, 'admin', 'Administrator', 'active'),
    ('550e8400-e29b-41d4-a716-446655440202'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, 'user', 'Regular User', 'active'),
    ('550e8400-e29b-41d4-a716-446655440203'::uuid, '550e8400-e29b-41d4-a716-446655440002'::uuid, 'admin', 'Administrator', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO permissions (id, tenant_id, name, description, resource, action) VALUES
    ('550e8400-e29b-41d4-a716-446655440301'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, 'user:read', 'Read user data', 'user', 'read'),
    ('550e8400-e29b-41d4-a716-446655440302'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, 'user:write', 'Write user data', 'user', 'write'),
    ('550e8400-e29b-41d4-a716-446655440303'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, 'admin:*', 'Admin access', 'admin', '*')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('550e8400-e29b-41d4-a716-446655440201'::uuid, '550e8400-e29b-41d4-a716-446655440301'::uuid),
    ('550e8400-e29b-41d4-a716-446655440201'::uuid, '550e8400-e29b-41d4-a716-446655440302'::uuid),
    ('550e8400-e29b-41d4-a716-446655440201'::uuid, '550e8400-e29b-41d4-a716-446655440303'::uuid),
    ('550e8400-e29b-41d4-a716-446655440202'::uuid, '550e8400-e29b-41d4-a716-446655440301'::uuid)
ON CONFLICT DO NOTHING;

INSERT INTO user_tenants (user_id, tenant_id, role_id, status) VALUES
    ('550e8400-e29b-41d4-a716-446655440101'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, '550e8400-e29b-41d4-a716-446655440201'::uuid, 'active'),
    ('550e8400-e29b-41d4-a716-446655440102'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, '550e8400-e29b-41d4-a716-446655440202'::uuid, 'active'),
    ('550e8400-e29b-41d4-a716-446655440103'::uuid, '550e8400-e29b-41d4-a716-446655440002'::uuid, '550e8400-e29b-41d4-a716-446655440203'::uuid, 'active')
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES
    ('550e8400-e29b-41d4-a716-446655440101'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, '550e8400-e29b-41d4-a716-446655440201'::uuid),
    ('550e8400-e29b-41d4-a716-446655440102'::uuid, '550e8400-e29b-41d4-a716-446655440001'::uuid, '550e8400-e29b-41d4-a716-446655440202'::uuid),
    ('550e8400-e29b-41d4-a716-446655440103'::uuid, '550e8400-e29b-41d4-a716-446655440002'::uuid, '550e8400-e29b-41d4-a716-446655440203'::uuid)
ON CONFLICT DO NOTHING;
