package saramakeycloak

import (
	"net/url"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	defaultRefreshThreshold      = 10 * time.Second
	defaultKeycloakTimeout       = 2 * time.Second
	defaultKeycloakRetryInterval = 100 * time.Millisecond
)

var (
	errorInvalidHostPort            = errors.New("keycloak hostport is invalid")
	errorInvalidCredentials         = errors.New("clientID & clientSecret must be specified")
	errorInvalidRealm               = errors.New("realm must be specified")
	errInvalidRefreshThreshold      = errors.New("refresh threshold must be positive")
	errInvalidKeycloakTimeout       = errors.New("keycloak timeout must be positive")
	errInvalidKeycloakRetryInterval = errors.New("keycloak timeout must be positive")
)

// Config defines configuration for Provider.
type Config struct {
	// KeycloakHostPort is address where keyacloak is running.
	KeycloakHostPort string
	// KeycloakTimeout defines timeouts for keycloak requests.
	KeycloakTimeout time.Duration
	// KeycloakRetryInterval defines retry interval between login / refresh attempts.
	KeycloakRetryInterval time.Duration

	ClientID     string // ClientID is an OpenID client identifier.
	ClientSecret string // ClientSecret is an OpenID client secret.
	Realm        string // Realm used to authenticate in.

	// RefreshThreshold specifies period before expiration when it will be refreshed.
	// If token TTL is 300s and RefreshThreshold is 5s then it will be refreshed after 295s.
	// It used to avoid situations when valid token is passed to Kafka, but when Kafka performs authorization it can expire because of TTL.
	RefreshThreshold time.Duration

	Logger *zap.Logger
}

func (c *Config) applyDefaults() {
	if c.RefreshThreshold == 0 {
		c.RefreshThreshold = defaultRefreshThreshold
	}

	if c.KeycloakTimeout == 0 {
		c.KeycloakTimeout = defaultKeycloakTimeout
	}

	if c.KeycloakRetryInterval == 0 {
		c.KeycloakRetryInterval = defaultKeycloakRetryInterval
	}

	if c.Logger == nil {
		c.Logger = zap.NewNop()
	}
}

func (c Config) validate() error {
	if c.ClientID == "" || c.ClientSecret == "" {
		return errorInvalidCredentials
	}

	if c.Realm == "" {
		return errorInvalidRealm
	}

	if u, err := url.Parse(c.KeycloakHostPort); err != nil || u.Host == "" {
		return errorInvalidHostPort
	}

	if c.RefreshThreshold < 0 {
		return errInvalidRefreshThreshold
	}

	if c.KeycloakTimeout < 0 {
		return errInvalidKeycloakTimeout
	}

	if c.KeycloakRetryInterval < 0 {
		return errInvalidKeycloakRetryInterval
	}

	return nil
}
