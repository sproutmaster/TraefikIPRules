package TraefikIPRules_test

import (
	"context"
	"github.com/sproutmaster/TraefikIPRules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		desc          string
		deny          []string
		allow         []string
		precedence    string
		expectedError bool
	}{
		{
			desc:          "invalid IP in deny list",
			deny:          []string{"invalid-ip"},
			allow:         []string{},
			expectedError: true,
		},
		{
			desc:          "invalid IP in allow list",
			deny:          []string{},
			allow:         []string{"invalid-ip"},
			expectedError: true,
		},
		{
			desc:          "invalid CIDR in deny list",
			deny:          []string{"192.168.1.0/33"},
			allow:         []string{},
			expectedError: true,
		},
		{
			desc:          "invalid IP range format",
			deny:          []string{"192.168.1.1-invalid"},
			allow:         []string{},
			expectedError: true,
		},
		{
			desc:          "invalid IP range (start > end)",
			deny:          []string{"192.168.1.100-192.168.1.1"},
			allow:         []string{},
			expectedError: true,
		},
		{
			desc:          "invalid precedence value",
			deny:          []string{},
			allow:         []string{},
			precedence:    "invalid",
			expectedError: true,
		},
		{
			desc:       "valid configuration with all rule types",
			deny:       []string{"192.168.1.0/24", "10.0.0.1", "172.16.1.1-172.16.1.255"},
			allow:      []string{"192.168.2.0/24", "10.0.0.2", "172.16.2.1-172.16.2.255"},
			precedence: "deny",
		},
		{
			desc:       "empty configuration",
			deny:       []string{},
			allow:      []string{},
			precedence: "deny",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := TraefikIPRules.CreateConfig()
			cfg.Deny = test.deny
			cfg.Allow = test.allow
			cfg.Precedence = test.precedence

			ctx := context.Background()
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			handler, err := TraefikIPRules.New(ctx, next, cfg, "ipRule plugin")

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
		deny       []string
		allow      []string
		precedence string
		remoteAddr string
		xff        string
		expected   int
	}{
		{
			desc:       "deny by default with no rules",
			deny:       []string{},
			allow:      []string{},
			precedence: "deny",
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in deny list (CIDR)",
			deny:       []string{"192.168.1.0/24"},
			allow:      []string{"10.0.0.0/8"},
			precedence: "deny",
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in deny list (specific IP)",
			deny:       []string{"10.0.0.1"},
			allow:      []string{"10.0.0.0/8"},
			precedence: "deny",
			remoteAddr: "10.0.0.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in deny range",
			deny:       []string{"192.168.1.1-192.168.1.255"},
			allow:      []string{"192.168.1.0/24"},
			precedence: "deny",
			remoteAddr: "192.168.1.100:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in allow list but not in deny",
			deny:       []string{"192.168.2.0/24"},
			allow:      []string{"192.168.1.0/24"},
			precedence: "deny",
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "IP in allow range",
			deny:       []string{},
			allow:      []string{"192.168.1.1-192.168.1.255"},
			precedence: "deny",
			remoteAddr: "192.168.1.100:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "IP not in allow list",
			deny:       []string{},
			allow:      []string{"192.168.1.0/24"},
			precedence: "deny",
			remoteAddr: "192.168.2.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in both deny and allow list with deny precedence",
			deny:       []string{"192.168.1.0/24"},
			allow:      []string{"192.168.1.0/24"},
			precedence: "deny",
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP in both deny and allow list with allow precedence",
			deny:       []string{"192.168.1.0/24"},
			allow:      []string{"192.168.1.0/24"},
			precedence: "allow",
			remoteAddr: "192.168.1.1:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "invalid remote address",
			deny:       []string{},
			allow:      []string{"192.168.1.0/24"},
			precedence: "deny",
			remoteAddr: "invalid-ip",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP with X-Forwarded-For in deny list",
			deny:       []string{"192.168.1.0/24"},
			allow:      []string{"10.0.0.0/8"},
			precedence: "deny",
			remoteAddr: "10.0.0.1:1234",
			xff:        "192.168.1.1, 10.0.0.1",
			expected:   http.StatusForbidden,
		},
		{
			desc:       "IP with X-Forwarded-For in allow list",
			deny:       []string{},
			allow:      []string{"192.168.1.0/24"},
			precedence: "deny",
			remoteAddr: "10.0.0.1:1234",
			xff:        "192.168.1.1, 10.0.0.1",
			expected:   http.StatusOK,
		},
		{
			desc:       "IP in allow range but also in deny range with allow precedence",
			deny:       []string{"192.168.1.1-192.168.1.255"},
			allow:      []string{"192.168.1.100-192.168.1.200"},
			precedence: "allow",
			remoteAddr: "192.168.1.150:1234",
			expected:   http.StatusOK,
		},
		{
			desc:       "IP in allow range but also in deny range with deny precedence",
			deny:       []string{"192.168.1.1-192.168.1.255"},
			allow:      []string{"192.168.1.100-192.168.1.200"},
			precedence: "deny",
			remoteAddr: "192.168.1.150:1234",
			expected:   http.StatusForbidden,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := TraefikIPRules.CreateConfig()
			cfg.Deny = test.deny
			cfg.Allow = test.allow
			cfg.Precedence = test.precedence

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
			recorder := httptest.NewRecorder()

			handler, err := TraefikIPRules.New(ctx, next, cfg, "ip-processor-plugin")
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
	cfg := TraefikIPRules.CreateConfig()
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.Deny)
	assert.Empty(t, cfg.Allow)
	assert.Equal(t, "deny", cfg.Precedence)
}
