package saramakeycloak

import (
	"context"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v5"
	"github.com/Shopify/sarama"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var (
	// ErrAlreadyClosed means that Provider was already closed before.
	ErrAlreadyClosed = errors.New("provider is already closed")
)

type token struct {
	jwt       *gocloak.JWT
	expiresAt time.Time // absolute time when access token expires.
}

func newToken(jwt *gocloak.JWT) *token {
	return &token{
		jwt:       jwt,
		expiresAt: time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second),
	}
}

func (t *token) activeNow() bool {
	if t == nil {
		return false
	}

	return time.Now().Before(t.expiresAt)
}

func (t *token) toSaramaToken() *sarama.AccessToken {
	return &sarama.AccessToken{Token: t.jwt.AccessToken}
}

// Provider is used to use keycloak as authentication provider for kafka.
// It implements sarama.AccessTokenProvider interface.
type Provider struct {
	logger *zap.Logger

	keycloak              Keycloak
	keycloakTimeout       time.Duration
	keycloakRetryInterval time.Duration

	// credentials to authenticate in keycloak.
	clientID     string
	clientSecret string
	realm        string

	refreshThreshold time.Duration

	tokenMu   *sync.RWMutex // guards token.
	tokenCond *sync.Cond
	token     *token // current active token.

	stopOnce sync.Once
	stopCh   chan struct{}
}

// New returns new Provider.
func New(c Config) (*Provider, error) {
	c.applyDefaults()

	if err := c.validate(); err != nil {
		return nil, errors.Wrap(err, "config validation failed")
	}

	mu := &sync.RWMutex{}

	p := &Provider{
		refreshThreshold:      c.RefreshThreshold,
		keycloak:              &keycloakWithMetrics{gocloak.NewClient(c.KeycloakHostPort)},
		keycloakTimeout:       c.KeycloakTimeout,
		keycloakRetryInterval: c.KeycloakRetryInterval,
		clientID:              c.ClientID,
		clientSecret:          c.ClientSecret,
		realm:                 c.Realm,
		logger:                c.Logger,
		tokenMu:               mu,
		tokenCond:             sync.NewCond(mu),
		stopCh:                make(chan struct{}),
		stopOnce:              sync.Once{},
	}

	go p.updateLoop()

	return p, nil
}

func (p *Provider) updateLoop() {
	onTokenUpdate := func(t *time.Timer, token *token) {
		resetIn := p.keycloakRetryInterval

		if token != nil {
			p.logger.Debug(
				"set new token",
				zap.String("token", token.jwt.AccessToken),
			)

			p.token = token

			resetIn = time.Duration(token.jwt.ExpiresIn) * time.Second
			if resetIn > p.refreshThreshold {
				resetIn = resetIn - p.refreshThreshold
			}
		}

		p.tokenCond.Broadcast()

		p.logger.Debug("next keycloak request scheduled", zap.Duration("reset", resetIn))

		t.Reset(resetIn)
	}

	t := time.NewTimer(0)
	defer t.Stop()

	for {
		select {
		case <-p.stopCh:
			p.logger.Warn("keycloak token provider stopped")
			return
		case <-t.C:
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), p.keycloakTimeout)
				defer cancel()

				p.tokenMu.Lock()
				defer p.tokenMu.Unlock()

				// if there is no active token then request new one.
				if p.token == nil {
					token, err := p.requestNewToken(ctx)
					if err != nil {
						p.logger.Error("failed to get keycloak token", zap.Error(err))
						onTokenUpdate(t, nil)
						return
					}

					onTokenUpdate(t, token)
					return
				}

				// refresh token
				token, err := p.refreshToken(ctx, p.token)
				if err != nil {
					p.logger.Error("failed to refresh token", zap.Error(err))

					onTokenUpdate(t, nil)
					return
				}

				onTokenUpdate(t, token)
			}()
		}
	}
}

// Token returns an access token.
func (p *Provider) Token() (*sarama.AccessToken, error) {
	p.tokenMu.RLock()
	token := p.token
	p.tokenMu.RUnlock()

	if token.activeNow() {
		return token.toSaramaToken(), nil
	}

	start := time.Now()
	p.tokenMu.Lock()
	for !p.token.activeNow() {
		p.tokenCond.Wait()

		// we don't want to block forever here.
		if time.Since(start) > p.keycloakTimeout {
			p.tokenMu.Unlock()
			return nil, context.DeadlineExceeded
		}
	}
	token = p.token
	p.tokenMu.Unlock()

	return token.toSaramaToken(), nil
}

// Close stops the background task for updating tokens.
func (p *Provider) Close() error {
	err := ErrAlreadyClosed

	p.stopOnce.Do(func() {
		close(p.stopCh)
		err = nil
	})

	return err
}

type tokenAsyncResult struct {
	token *gocloak.JWT
	err   error
}

func (p *Provider) requestNewToken(ctx context.Context) (*token, error) {
	resCh := make(chan tokenAsyncResult, 1)
	go func() {
		token, err := p.keycloak.LoginClient(p.clientID, p.clientSecret, p.realm)
		resCh <- tokenAsyncResult{token: token, err: errors.Wrap(err, "gocloak: login failed")}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}

		return newToken(res.token), nil
	}
}

func (p *Provider) refreshToken(ctx context.Context, old *token) (*token, error) {
	resCh := make(chan tokenAsyncResult, 1)
	go func() {
		token, err := p.keycloak.RefreshToken(old.jwt.RefreshToken, p.clientID, p.clientSecret, p.realm)
		resCh <- tokenAsyncResult{token: token, err: errors.Wrap(err, "gocloak: refresh failed")}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}

		return newToken(res.token), nil
	}
}
