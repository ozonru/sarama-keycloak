package saramakeycloak

import (
	"testing"

	"github.com/Nerzal/gocloak"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	clientID     = "client-id"
	clientSecret = "client-secret"
	realm        = "realm"
)

func TestProviderGetNewToken(t *testing.T) {
	p, mock := newProvider(t)
	defer mock.MinimockFinish()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 0, "", 0), nil)

	token, err := p.Token()

	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderReturnCurrentToken(t *testing.T) {
	p, mock := newProvider(t)
	defer mock.MinimockFinish()

	defer func() {
		assert.Len(t, mock.LoginClientMock.Calls(), 1)
	}()

	mock.LoginClientMock.
		Expect(clientID, clientSecret, realm).
		Return(newJWT("token", 10, "", 0), nil)

	_, _ = p.Token()        // first call requests token from keycloak
	token, err := p.Token() // second one must reuse it
	assert.NoError(t, err)
	assert.Equal(t, "token", token.Token)
}

func TestProviderLoginFailed(t *testing.T) {
	p, mock := newProvider(t)
	defer mock.MinimockFinish()

	expectedErr := errors.New("some error")
	mock.LoginClientMock.Return(nil, expectedErr)

	token, err := p.Token()

	assert.Nil(t, token)
	assert.Equal(t, expectedErr, errors.Cause(err))
}

func TestProviderRefreshToken(t *testing.T) {
	p, mock := newProvider(t)
	defer mock.MinimockFinish()

	mock.LoginClientMock.Return(newJWT("token", 0, "r-token", 10), nil)

	mock.RefreshTokenMock.Expect(
		"r-token",
		clientID,
		clientSecret,
		realm,
	).Return(newJWT("token-2", 0, "r-token-2", 10), nil)

	token, _ := p.Token()
	assert.Equal(t, "token", token.Token)

	token, _ = p.Token()
	assert.Equal(t, "token-2", token.Token)
}

func TestProviderRefreshTokenFailed(t *testing.T) {
	p, mock := newProvider(t)
	defer mock.MinimockFinish()

	mock.LoginClientMock.Return(newJWT("token", 0, "r-token", 10), nil)

	expectedErr := errors.New("some error")
	mock.RefreshTokenMock.Return(nil, expectedErr)

	token, _ := p.Token()
	assert.Equal(t, "token", token.Token)

	token, err := p.Token()
	assert.Nil(t, token)
	assert.Equal(t, expectedErr, errors.Cause(err))
}

// newProvider returns Provider and mocked Keycloak client.
func newProvider(t *testing.T) (*Provider, *GoCloakMock) {
	c := Config{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		Realm:            realm,
		KeycloakHostPort: "https://localhost",
	}

	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	mock := NewGoCloakMock(t)

	p.setClient(mock)

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
