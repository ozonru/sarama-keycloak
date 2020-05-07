package saramakeycloak

import (
	"sync"
	"time"

	"github.com/Nerzal/gocloak"
	"github.com/Shopify/sarama"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Config defines configuration for Provider.
type Config struct {
	// KeycloackHostPort is adress where keyacloak is running.
	KeycloackHostPort string

	ClientID     string // ClientID is an OpenID client identifier.
	ClientSecret string // ClientSecret is an OpenID client secret.
	Realm        string // Realm used to authenticate in.

	Logger *zap.Logger
}

// Provider is used to use keycloak as authentication provider for kafka.
// It implements sarama.AccessTokenProvider interface.
type Provider struct {
	keycloak gocloak.GoCloak

	// credentials to authenticate in keycloak.
	clientID     string
	clientSecret string
	realm        string

	delta time.Duration

	tokenMu          sync.RWMutex // guards token and expiration info.
	token            *gocloak.JWT // current active token.
	expiresAt        time.Time    // absolute time when access token expires.
	refreshExpiresAt time.Time    // absolute time when refresh token expires.

	logger *zap.Logger
}

// NewProvider returns new Provider.
func NewProvider(c Config) *Provider {
	if c.Logger == nil {
		c.Logger = zap.NewNop()
	}

	return &Provider{
		delta:        30 * time.Second,
		keycloak:     gocloak.NewClient(c.KeycloackHostPort),
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		realm:        c.Realm,
		logger:       c.Logger,
	}
}

// Token returns an access token.
func (p *Provider) Token() (*sarama.AccessToken, error) {
	p.logger.Debug("retrieve token attempt")

	token, err := p.getActiveToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token")
	}

	return &sarama.AccessToken{Token: token.AccessToken}, nil
}

func (p *Provider) setToken(token *gocloak.JWT) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	p.token = token
	p.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	p.refreshExpiresAt = time.Now().Add(time.Duration(token.RefreshExpiresIn) * time.Second)

	p.logger.Debug("token saved", zap.Time("expires_at", p.expiresAt), zap.Time("refresh_expires_at", p.refreshExpiresAt))
}

// getNewToken requests new token for client.
func (p *Provider) requestNewToken() (*gocloak.JWT, error) {
	token, err := p.keycloak.LoginClient(p.clientID, p.clientSecret, p.realm)

	return token, errors.Wrap(err, "gocloak: login failed")
}

func (p *Provider) refreshToken(old *gocloak.JWT) (*gocloak.JWT, error) {
	token, err := p.keycloak.RefreshToken(old.RefreshToken, p.clientID, p.clientSecret, p.realm)

	return token, errors.Wrap(err, "gocloak: refresh failed")
}

func (p *Provider) getActiveToken() (*gocloak.JWT, error) {
	p.tokenMu.RLock()

	// check that current token isn't expired
	if time.Now().Add(p.delta).Before(p.expiresAt) {
		token := p.token
		p.tokenMu.RUnlock()

		p.logger.Debug("current token is valid")

		return token, nil
	}

	// if expired but refresh token is alive, than refresh it
	if time.Now().Add(p.delta).Before(p.refreshExpiresAt) {
		p.logger.Debug("refresh current token")
		token, err := p.refreshToken(p.token)
		// despite of result it's required to release read lock here.
		// if refresh is sucessful it will be overwritten below.
		p.tokenMu.RUnlock()
		if err != nil {
			return nil, errors.Wrap(err, "refresh failed")
		}

		p.logger.Debug("refreshed")

		p.setToken(token)

		return token, nil
	}

	p.tokenMu.RUnlock()

	// otherwise request new token

	p.logger.Debug("request new token")
	token, err := p.requestNewToken()
	if err != nil {
		return nil, errors.Wrap(err, "request new token failed")
	}

	p.setToken(token)

	return token, nil
}
