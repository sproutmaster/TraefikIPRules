package traefikiprules_test

import (
	"context"
	traefikiprules "github.com/sproutmaster/TraefikIPRules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		desc          string
		denyList      []string
		allowList     []string
		expectedError bool
	}{
		{
			desc:          "invalid IP in deny list",
			denyList:      []string{"invalid-ip"},
			allowList:     []string{},
			expectedError: true,
		},
		{
			desc:          "invalid IP in allow list",
			denyList:      []string{},
			allowList:     []string{"invalid-ip"},
			expectedError: true,
		},
		{
			desc:          "invalid CIDR in deny list",
			denyList:      []string{"192.168.1.0/33"},
			allowList:     []string{},
			expectedError: true,
		},
		{
			desc:      "valid configuration",
			denyList:  []string{"192.168.1.0/24", "10.0.0.1"},
			allowList: []string{"192.168.2.0/24", "10.0.0.2"},
		},
		{
			desc:      "empty configuration",
			denyList:  []string{},
			allowList: []string{},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := traefikiprules.CreateConfig()
			cfg.DenyList = test.denyList
			cfg.AllowList = test.allowList

			ctx := context.Background()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			handler, err := traefikiprules.New(ctx, next, cfg, "ipRule plugin")

			if test.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, handler)
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	testCases := []struct {
		desc       string
		denyList   []string
		allowList  []string
		remoteAddr string
		xff        string
		expected   int
	}{
		{
			desc:       "allowed IP with no rules",
			denyList:   []string{},
			allowList:  []string{},
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "IP in deny list",
			denyList:   []string{"192.168.1.0/24"},
			allowList:  []string{},
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in deny list (specific IP)",
			denyList:   []string{"10.0.0.1"},
			allowList:  []string{},
			remoteAddr: "10.0.0.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in allow list",
			denyList:   []string{},
			allowList:  []string{"192.168.1.0/24"},
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "IP not in allow list",
			denyList:   []string{},
			allowList:  []string{"192.168.1.0/24"},
			remoteAddr: "192.168.2.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in deny and allow list",
			denyList:   []string{"192.168.1.0/24"},
			allowList:  []string{"192.168.1.0/24"},
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "block subnet but allow everything else",
			denyList:   []string{"192.168.1.0/24"},
			allowList:  []string{"0.0.0.0/0"},
			remoteAddr: "10.0.0.1:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "block subnet and verify it's blocked even with allow all",
			denyList:   []string{"192.168.1.0/24"},
			allowList:  []string{"0.0.0.0/0"},
			remoteAddr: "192.168.1.100:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "invalid remote address",
			denyList:   []string{},
			allowList:  []string{},
			remoteAddr: "invalid-ip",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP with X-Forwarded-For",
			denyList:   []string{"192.168.1.0/24"},
			allowList:  []string{},
			remoteAddr: "10.0.0.1:1234",
			xff:        "192.168.1.1, 10.0.0.1",
			expected:   http.StatusForbidden,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := traefikiprules.CreateConfig()
			cfg.DenyList = test.denyList
			cfg.AllowList = test.allowList

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
			recorder := httptest.NewRecorder()

			handler, err := traefikiprules.New(ctx, next, cfg, "ip-processor-plugin")
			require.NoError(t, err)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			require.NoError(t, err)

			if test.remoteAddr != "" {
				req.RemoteAddr = test.remoteAddr
			}
			if test.xff != "" {
				req.Header.Add("X-Forwarded-For", test.xff)
			}

			handler.ServeHTTP(recorder, req)
			assert.Equal(t, test.expected, recorder.Code)
		})
	}
}

func TestCreateConfig(t *testing.T) {
	cfg := traefikiprules.CreateConfig()
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.DenyList)
	assert.Empty(t, cfg.AllowList)
}
