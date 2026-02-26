// Package iam provides a Go SDK for Valhalla IAM service.
//
// It enables any Go service to integrate with Valhalla's centralized
// authentication, authorization, and multi-tenancy capabilities.
package iam

import (
	"fmt"
)

// Client is the main entry point for interacting with Valhalla IAM.
type Client struct {
	config Config
}

// Config holds the configuration for connecting to Valhalla IAM.
type Config struct {
	// Endpoint is the gRPC address of the Valhalla IAM service.
	// Example: "valhalla-iam:9000"
	Endpoint string

	// JWKSUrl is the URL to fetch JWKS public keys for local JWT verification.
	// Example: "http://valhalla:8080/.well-known/jwks.json"
	JWKSUrl string

	// APIKey is the public identifier for service-to-service authentication.
	APIKey string

	// APISecret is the private key for service-to-service authentication.
	APISecret string

	// CacheTTL is how long to cache permission decisions locally.
	// Default: 5 minutes.
	CacheTTL int

	// TLSEnabled enables TLS for gRPC connection.
	TLSEnabled bool

	// TLSCertPath is the path to the TLS certificate file.
	TLSCertPath string
}

// NewClient creates a new IAM client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("iam: endpoint is required")
	}

	return &Client{
		config: cfg,
	}, nil
}

// Close releases all resources held by the client.
func (c *Client) Close() error {
	// TODO: close gRPC connection, stop JWKS refresh, etc.
	return nil
}
