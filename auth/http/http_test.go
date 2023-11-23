package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/stretchr/testify/require"
)

var defaultClientID = "default_client_id"

func TestID(t *testing.T) {
	authHook := new(Hook)

	require.Equal(t, "http-auth-hook", authHook.ID())
}

func TestProvides(t *testing.T) {
	authHook := new(Hook)

	tests := []struct {
		name           string
		hook           byte
		expectProvides bool
	}{
		{
			name:           "Success - Provides OnACLCheck",
			hook:           mqtt.OnACLCheck,
			expectProvides: true,
		},
		{
			name:           "Success - Provides OnConnectAuthenticate",
			hook:           mqtt.OnConnectAuthenticate,
			expectProvides: true,
		},
		{
			name:           "Failure - Provides other hook",
			hook:           mqtt.OnClientExpired,
			expectProvides: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			require.Equal(t, tt.expectProvides, authHook.Provides(tt.hook))

		})
	}
}

func TestInit(t *testing.T) {
	authHook := new(Hook)
	authHook.Log = slog.Default()

	tests := []struct {
		name        string
		config      any
		expectError bool
	}{
		{
			name: "Success - Proper config",
			config: Options{
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectError: false,
		},
		{
			name: "Success - Proper config - callback function",
			config: Options{
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
				Callback:                 func(resp *http.Response) bool { return true },
			},
			expectError: false,
		},
		{
			name:        "Failure - nil config",
			config:      nil,
			expectError: true,
		},
		{
			name:        "Failure - improper config",
			config:      "",
			expectError: true,
		},
		{
			name:        "Failure - hostname validation fail",
			config:      Options{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := authHook.Init(tt.config)
			if tt.expectError {
				require.Error(t, err)
			}

		})
	}
}

func TestOnACLCheck(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	tests := []struct {
		name           string
		config         any
		clientBlockMap map[string]time.Time
		mocks          func(ctx context.Context)
		expectPass     bool
	}{
		{
			name: "Success - Proper config",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: true,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
				}, nil)

			},
		},
		{
			name: "Success - Proper config - Timeout Configured - Not Blocked",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: true,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
				}, nil)

			},
		},
		{
			name: "Success - Proper config - Timeout Configured - Should Block",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: false,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusUnauthorized,
				}, nil)

			},
		},
		{
			name: "Success - Proper config - Timeout Configured - Should Delete Client From Block Map",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			clientBlockMap: map[string]time.Time{
				defaultClientID: time.Now().Add(-1 * time.Hour),
			},
			expectPass: true,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
				}, nil)

			},
		},
		{
			name: "Error - HTTP error",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: false,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("Oh Crap"))
			},
		},
		{
			name: "Error - Non 2xx",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: false,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusTeapot,
				}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.mocks(ctx)

			authHook := new(Hook)
			authHook.Log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
			authHook.Init(tt.config)

			success := authHook.OnACLCheck(&mqtt.Client{
				ID: defaultClientID,
			}, "/topic", false)

			require.Equal(t, tt.expectPass, success)
		})
	}
}

func TestOnConnectAuthenticate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	tests := []struct {
		name       string
		config     any
		mocks      func(ctx context.Context)
		expectPass bool
	}{
		{
			name: "Success - Proper config",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: true,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
				}, nil)

			},
		},
		{
			name: "Success - Proper config - Timeout Configured - Not Blocked",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: true,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
				}, nil)

			},
		},
		{
			name: "Success - Proper config - Timeout Configured - Should Block",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: false,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusUnauthorized,
				}, nil)

			},
		},
		{
			name: "Error - HTTP error",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: false,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("Oh Crap"))
			},
		},
		{
			name: "Error - Non 2xx",
			config: Options{
				RoundTripper:             mockRT,
				ACLHost:                  stringToURL("http://aclhost.com"),
				ClientAuthenticationHost: stringToURL("http://clientauthenticationhost.com"),
			},
			expectPass: false,
			mocks: func(ctx context.Context) {
				mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusTeapot,
				}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.mocks(ctx)

			authHook := new(Hook)
			authHook.Log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
			authHook.Init(tt.config)

			success := authHook.OnConnectAuthenticate(&mqtt.Client{
				ID: defaultClientID,
			}, packets.Packet{})
			require.Equal(t, tt.expectPass, success)
		})
	}
}

func stringToURL(s string) *url.URL {
	parsedURL, _ := url.Parse(s)
	return parsedURL
}
