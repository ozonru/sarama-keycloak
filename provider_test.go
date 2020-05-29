package saramakeycloak

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	clientID     = "client-id"
	clientSecret = "client-secret"
	realm        = "realm"
)

func TestNewProviderInvalidConfig(t *testing.T) {
	p, err := New(Config{})

	assert.Nil(t, p)
	assert.Error(t, err)
}

func TestProviderGetNewToken(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 1, "", 0), nil)

	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderReturnActiveToken(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 1, "", 0), nil)

	p.Token()
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderLoginClientAttemptFails(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	var calls int
	mock.LoginClientMock.Set(func(_, _, _ string) (*gocloak.JWT, error) {
		if calls == 0 {
			calls++
			return nil, errors.New("some error")
		}

		return newJWT("token", 1, "", 0), nil
	})

	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderTokenTimeout(t *testing.T) {
	p, mock := newProvider(t)
	p.keycloakTimeout = time.Nanosecond // must immediately timeouts
	defer p.Close()
	defer mock.MinimockWait(time.Second)

	mock.LoginClientMock.Set(func(clientID string, clientSecret string, realm string) (jp1 *gocloak.JWT, err error) {
		time.Sleep(time.Millisecond)

		return newJWT("token", 60, "", 0), nil

	})

	token, err := p.Token()

	assert.Nil(t, token)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestProviderRefreshToken(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 0, "r-token", 0), nil)

	refreshed := make(chan struct{})
	mock.
		RefreshTokenMock.
		Set(
			func(_refreshToken, _clientID, _clientSecret, _realm string) (*gocloak.JWT, error) {
				defer func() {
					p.Close()
					close(refreshed)
				}()

				assert.Equal(t, clientID, _clientID)
				assert.Equal(t, clientSecret, _clientSecret)
				assert.Equal(t, realm, _realm)
				assert.Equal(t, "r-token", _refreshToken)

				return newJWT("token-2", 1, "r-token-2", 10), nil
			},
		)

	p.Token()
	<-refreshed
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token-2", token.Token)
}

func TestProviderRefreshFails(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.
		LoginClientMock.
		Return(newJWT("token", 1, "r-token", 5), nil)

	refreshed := make(chan struct{})
	mock.
		RefreshTokenMock.
		Set(func(_, _, _, _ string) (jp1 *gocloak.JWT, err error) {
			defer func() {
				refreshed <- struct{}{}
			}()
			return nil, errors.New("some error")
		})

	p.Token()
	<-refreshed
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderRefreshTokenTimeouts(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockWait(time.Second)

	mock.LoginClientMock.
		Return(newJWT("token", 1, "r-token", 0), nil)

	ch := make(chan struct{})
	defer close(ch)

	mock.RefreshTokenMock.
		Set(func(_, _, _, _ string) (*gocloak.JWT, error) {
			time.Sleep(110 * time.Millisecond)
			return newJWT("token-2", 6, "r-token-2", 10), nil
		})

	p.Token()
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

// newProvider returns Provider and mocked Keycloak client.
func newProvider(t *testing.T) (*Provider, *KeycloakMock) {
	cfg := zap.NewDevelopmentConfig()
	cfg.DisableStacktrace = true
	l, _ := cfg.Build()

	c := Config{
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		Realm:                 realm,
		KeycloakHostPort:      "https://localhost",
		KeycloakTimeout:       100 * time.Millisecond,
		KeycloakRetryInterval: 10 * time.Millisecond,
		RefreshThreshold:      900 * time.Millisecond,
		Logger:                l,
	}

	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	mock := NewKeycloakMock(t)

	p.keycloak = mock

	return p, mock
}

func newJWT(accessToken string, expiresIn int, refreshToken string, RefreshExpiresIn int) *gocloak.JWT {
	return &gocloak.JWT{
		AccessToken:      accessToken,
		ExpiresIn:        expiresIn,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: RefreshExpiresIn,
	}
}
