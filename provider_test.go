package saramakeycloak

import (
	"errors"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v5"
	"github.com/stretchr/testify/assert"
)

const (
	clientID     = "client-id"
	clientSecret = "client-secret"
	realm        = "realm"
)

func TestProviderGetNewToken(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 60, "", 0), nil)

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
		Return(newJWT("token", 60, "", 0), nil)

	p.Token()
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
	assert.Equal(t, uint64(1), mock.LoginClientAfterCounter())
}

func TestProviderLoginClientAttemptFails(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	var calls int
	mock.LoginClientMock.Set(func(clientID string, clientSecret string, realm string) (jp1 *gocloak.JWT, err error) {
		if calls == 0 {
			calls++
			return nil, errors.New("some error")
		}

		return newJWT("token", 60, "", 0), nil
	})

	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderRefreshToken(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 6, "r-token", 0), nil)

	mock.RefreshTokenMock.Expect(
		"r-token",
		clientID,
		clientSecret,
		realm,
	).Return(newJWT("token-2", 6, "r-token-2", 10), nil)

	p.Token()
	time.Sleep(1500 * time.Millisecond)
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token-2", token.Token)
	assert.Equal(t, uint64(1), mock.LoginClientAfterCounter())
}

func TestProviderRefreshAttemptFails(t *testing.T) {
	p, mock := newProvider(t)
	defer p.Close()
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 6, "r-token", 0), nil)

	mock.RefreshTokenMock.
		Expect("r-token", clientID, clientSecret, realm).
		Return(nil, errors.New("some error"))

	p.Token()
	time.Sleep(2000 * time.Millisecond)
	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
	assert.Equal(t, uint64(2), mock.LoginClientAfterCounter())
}

// newProvider returns Provider and mocked Keycloak client.
func newProvider(t *testing.T) (*Provider, *KeycloakMock) {
	c := Config{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		Realm:            realm,
		KeycloakHostPort: "https://localhost",
		KeycloakTimeout:  5 * time.Second,
		RefreshThreshold: 5 * time.Second,
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
