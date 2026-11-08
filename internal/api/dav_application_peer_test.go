package api

import (
	"strings"
	"testing"
)

// The peer gets no ambient cloud credentials, proxy or RCLONE_* configuration.
// Its explicit private config and CA are the only remote/authentication inputs.
func davApplicationEnvironment(environment []string) []string {
	var selected []string
	for _, pair := range environment {
		name, _, ok := strings.Cut(pair, "=")
		if ok && (name == "PATH" || name == "LANG" || name == "LC_ALL" || name == "TZ") {
			selected = append(selected, pair)
		}
	}
	return selected
}

func TestDAVApplicationCannotInheritRemoteAuthorityOrProxy(t *testing.T) {
	env := davApplicationEnvironment([]string{"PATH=/usr/bin", "LANG=C.UTF-8", "TZ=UTC",
		"RCLONE_CONFIG=other.conf", "RCLONE_CONFIG_FREIGHTCTL_URL=https://outside.invalid/",
		"RCLONE_CONFIG_FREIGHTCTL_BEARER_TOKEN=untrusted", "RCLONE_WEBDAV_AUTH_REDIRECT=true",
		"RCLONE_NO_CHECK_CERTIFICATE=true", "HTTPS_PROXY=https://outside.invalid/", "http_proxy=other",
		"AWS_SECRET_ACCESS_KEY=private", "GITHUB_TOKEN=private", "GOMAXPROCS=1", "GOMEMLIMIT=192MiB"})
	if strings.Join(env, "\n") != "PATH=/usr/bin\nLANG=C.UTF-8\nTZ=UTC" {
		t.Fatal("independent DAV application inherited ambient authority/configuration or copied build ceilings")
	}
}
