package saramakeycloak

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestConfigApplyDefaults(t *testing.T) {
	c := Config{}
	c.applyDefaults()

	assert.Equal(t, defaultRefreshThreshold, c.RefreshThreshold)
	assert.NotNil(t, c.Logger)
}

func TestConfigApplyDefaults_DontOverride(t *testing.T) {
	logger := zap.NewExample()
	c := Config{
		RefreshThreshold: time.Second,
		Logger:           logger,
	}

	c.applyDefaults()

	assert.Equal(t, time.Second, c.RefreshThreshold)
	assert.Equal(t, logger, c.Logger)
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		c   Config
		err error
	}{
		{
			c:   Config{},
			err: ErrorInvalidCredentials,
		},
		{
			c: Config{
				ClientID: "<client-id>",
			},
			err: ErrorInvalidCredentials,
		},
		{
			c: Config{
				ClientSecret: "<client-secret>",
			},
			err: ErrorInvalidCredentials,
		},
		{
			c: Config{
				ClientID:     "<client-id>",
				ClientSecret: "<client-secret>",
			},
			err: ErrorInvalidRealm,
		},
		{
			c: Config{
				ClientID:     "<client-id>",
				ClientSecret: "<client-secret>",
				Realm:        "<realm>",
			},
			err: ErrorInvalidHostPort,
		},
		{
			c: Config{
				ClientID:         "<client-id>",
				ClientSecret:     "<client-secret>",
				Realm:            "<realm>",
				KeycloakHostPort: "ht\\invalid",
			},
			err: ErrorInvalidHostPort,
		},
		{
			c: Config{
				ClientID:         "<client-id>",
				ClientSecret:     "<client-secret>",
				Realm:            "<realm>",
				KeycloakHostPort: "http://keycloak.host",
			},
		},
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			err := tc.c.validate()

			assert.Equal(t, tc.err, err)
		})
	}
}
