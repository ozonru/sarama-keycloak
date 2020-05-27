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
			err: errorInvalidCredentials,
		},
		{
			c: Config{
				ClientID: "<client-id>",
			},
			err: errorInvalidCredentials,
		},
		{
			c: Config{
				ClientSecret: "<client-secret>",
			},
			err: errorInvalidCredentials,
		},
		{
			c: Config{
				ClientID:     "<client-id>",
				ClientSecret: "<client-secret>",
			},
			err: errorInvalidRealm,
		},
		{
			c: Config{
				ClientID:     "<client-id>",
				ClientSecret: "<client-secret>",
				Realm:        "<realm>",
			},
			err: errorInvalidHostPort,
		},
		{
			c: Config{
				ClientID:         "<client-id>",
				ClientSecret:     "<client-secret>",
				Realm:            "<realm>",
				KeycloakHostPort: "ht\\invalid",
			},
			err: errorInvalidHostPort,
		},
		{
			c: Config{
				ClientID:         "<client-id>",
				ClientSecret:     "<client-secret>",
				Realm:            "<realm>",
				KeycloakHostPort: "http://keycloak.host",
				RefreshThreshold: -1,
			},
			err: errInvalidRefreshThreshold,
		},
		{
			c: Config{
				ClientID:         "<client-id>",
				ClientSecret:     "<client-secret>",
				Realm:            "<realm>",
				KeycloakHostPort: "http://keycloak.host",
				KeycloakTimeout:  -1,
			},
			err: errInvalidKeycloakTimeout,
		},
		{
			c: Config{
				ClientID:              "<client-id>",
				ClientSecret:          "<client-secret>",
				Realm:                 "<realm>",
				KeycloakHostPort:      "http://keycloak.host",
				KeycloakRetryInterval: -1,
			},
			err: errInvalidKeycloakRetryInterval,
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
