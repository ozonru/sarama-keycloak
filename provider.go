package saramakeycloak

import (
	"context"
	"sync"
	"time"

	"github.com/Nerzal/gocloak"
	"github.com/Shopify/sarama"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Provider is used to use keycloak as authentication provider for kafka.
// It implements sarama.AccessTokenProvider interface.
type Provider struct {
	keycloak        gocloak.GoCloak
	keycloakTimeout time.Duration

	// credentials to authenticate in keycloak.
	clientID     string
	clientSecret string
	realm        string

	refreshThreshold time.Duration

	tokenMu          sync.Mutex   // guards token and expiration info.
	token            *gocloak.JWT // current active token.
	expiresAt        time.Time    // absolute time when access token expires.
	refreshExpiresAt time.Time    // absolute time when refresh token expires.

	logger *zap.Logger
}

// New returns new Provider.
func New(c Config) (*Provider, error) {
	c.applyDefaults()

	return &Provider{
		refreshThreshold: c.RefreshThreshold,
		keycloak:         gocloak.NewClient(c.KeycloakHostPort),
		keycloakTimeout:  c.KeycloakTimeout,
		clientID:         c.ClientID,
		clientSecret:     c.ClientSecret,
		realm:            c.Realm,
		logger:           c.Logger,
	}, nil
}

// setClient sets internal keycloak client.
// must be used only for testing!
func (p *Provider) setClient(c gocloak.GoCloak) {
	p.keycloak = c
}

// Token returns an access token.
func (p *Provider) Token() (*sarama.AccessToken, error) {
	p.logger.Debug("retrieve token attempt")

	ctx, cancel := context.WithTimeout(context.Background(), p.keycloakTimeout)
	defer cancel()
	token, err := p.getActiveToken(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get token")
	}

	return &sarama.AccessToken{Token: token.AccessToken}, nil
}

func (p *Provider) getActiveToken(ctx context.Context) (*gocloak.JWT, error) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	// check that current token isn't expired
	if time.Now().Add(p.refreshThreshold).Before(p.expiresAt) {
		p.logger.Debug("current token is valid")

		return p.token, nil
	}

	// if expired but refresh token is alive, than refresh it
	if time.Now().Add(p.refreshThreshold).Before(p.refreshExpiresAt) {
		p.logger.Debug("current token must be refreshed")
		token, err := p.refreshToken(ctx, p.token)
		if err != nil {
			// if refresh failed, but current token is still active return it
			if time.Now().Before(p.expiresAt) {
				return p.token, nil
			}

			return nil, errors.Wrap(err, "refresh failed")
		}

		p.logger.Debug("refreshed")

		p.setToken(token)

		return token, nil
	}

	// otherwise request new token
	p.logger.Debug("request new token")
	token, err := p.requestNewToken(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "request new token failed")
	}

	p.setToken(token)

	return token, nil
}

type tokenAsyncResult struct {
	token *gocloak.JWT
	err   error
}

func (p *Provider) requestNewToken(ctx context.Context) (*gocloak.JWT, error) {
	resCh := make(chan tokenAsyncResult, 1)
	go func() {
		token, err := p.keycloak.LoginClient(p.clientID, p.clientSecret, p.realm)
		resCh <- tokenAsyncResult{token: token, err: errors.Wrap(err, "gocloak: login failed")}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		return res.token, res.err
	}
}

func (p *Provider) refreshToken(ctx context.Context, old *gocloak.JWT) (*gocloak.JWT, error) {
	resCh := make(chan tokenAsyncResult, 1)
	go func() {
		token, err := p.keycloak.RefreshToken(old.RefreshToken, p.clientID, p.clientSecret, p.realm)
		resCh <- tokenAsyncResult{token: token, err: errors.Wrap(err, "gocloak: refresh failed")}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		return res.token, res.err
	}
}

// setToken updates current active token and calculates expirations for it.
// It's not thread safe, so it must be guarded with tokenMu.
func (p *Provider) setToken(token *gocloak.JWT) {
	p.token = token
	p.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	p.refreshExpiresAt = time.Now().Add(time.Duration(token.RefreshExpiresIn) * time.Second)

	p.logger.Debug(
		"token saved",
		zap.Time("expires_at", p.expiresAt),
		zap.Time("refresh_expires_at", p.refreshExpiresAt),
	)
}
