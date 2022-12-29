package secretone

import (
	"os"
	"regexp"
	"testing"

	"github.com/wangchao475/secretone/internals/assert"
)

func TestClient_userAgent(t *testing.T) {
	cases := map[string]struct {
		appInfo       []*AppInfo
		envAppName    string
		envAppVersion string
		expected      string
		err           error
	}{
		"default": {},
		"multiple app info layers": {
			appInfo: []*AppInfo{
				{Name: "secretone-xgo", Version: "0.1.0"},
				{Name: "secretone-java", Version: "0.2.0"},
			},
			expected: "secretone-xgo/0.1.0 secretone-java/0.2.0",
		},
		"no version number": {
			appInfo: []*AppInfo{
				{Name: "terraform-provider-secretone"},
			},
			expected: "terraform-provider-secretone",
		},
		"top level app info from environment": {
			appInfo: []*AppInfo{
				{Name: "secretone-cli", Version: "0.37.0"},
			},
			envAppName:    "secretone-circleci-orb",
			envAppVersion: "1.0.0",
			expected:      "secretone-cli/0.37.0 secretone-circleci-orb/1.0.0",
		},
		"invalid app name": {
			appInfo: []*AppInfo{
				{Name: "illegal-name*%!@", Version: "0.1.0"},
			},
			err: ErrInvalidAppInfoName,
		},
		"ignore faulty environment variable": {
			appInfo: []*AppInfo{
				{Name: "secretone-cli", Version: "0.37.0"},
			},
			envAppName: "illegal-name*%!@",
			expected:   "secretone-cli/0.37.0",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			os.Setenv("SECRETONE_APP_INFO_NAME", tc.envAppName)
			os.Setenv("SECRETONE_APP_INFO_VERSION", tc.envAppVersion)

			var opts []ClientOption
			for _, info := range tc.appInfo {
				opts = append(opts, WithAppInfo(info))
			}
			client := &Client{}
			err := client.with(opts...)
			assert.Equal(t, err, tc.err)

			client.loadAppInfoFromEnv()

			userAgent := client.userAgent()
			pattern := tc.expected + " \\(.*\\)"
			matched, err := regexp.MatchString(pattern, userAgent)
			assert.OK(t, err)
			if !matched {
				t.Errorf("user agent '%s' doesn't match pattern '%s'", userAgent, pattern)
			}
		})
	}
}
