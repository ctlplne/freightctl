// Package scanner is the bounded local scanner protocol boundary. It never
// launches an engine, updates definitions, selects file paths for scanning or
// grants publication authority. Results still require ordinary check/release.
package scanner

import (
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Backend = "clamd-instream-v1"

var ErrInput = errors.New("invalid local scanner definition")
var ErrUnavailable = errors.New("scanner unavailable or unverified")
var ErrProtocol = errors.New("scanner reply is malformed, ambiguous or incomplete")
var ErrSource = errors.New("scanner stream differs from the exact accepted source")
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var enginePattern = regexp.MustCompile(`^1\.(4|5)\.[0-9]{1,4}$`)

type Definition struct {
	Schema              int       `json:"schema_version"`
	Kind                string    `json:"kind"`
	Socket              string    `json:"socket_reference"`
	Configuration       string    `json:"configuration_reference"`
	ConfigurationSHA256 string    `json:"configuration_sha256"`
	ExpectedVersion     string    `json:"expected_version"`
	ValidUntil          time.Time `json:"valid_until"`
	MaxBytes            int64     `json:"max_bytes"`
	TimeoutSeconds      int       `json:"timeout_seconds"`
	MaxResultAgeSeconds int       `json:"max_result_age_seconds"`
}
type Version struct {
	Engine       string `json:"engine_version"`
	Database     int64  `json:"database_version"`
	DatabaseDate string `json:"database_date"`
}
type Result struct {
	Backend             string  `json:"backend"`
	Version             Version `json:"version"`
	VersionSHA256       string  `json:"version_sha256"`
	ConfigurationSHA256 string  `json:"configuration_sha256"`
	Verdict             string  `json:"verdict"`
	DetectionSHA256     string  `json:"detection_sha256,omitempty"`
	ResponseSHA256      string  `json:"response_sha256"`
	Bytes               int64   `json:"bytes_scanned"`
	SHA256              string  `json:"sha256"`
}

func ParseVersion(value string) (Version, error) {
	var v Version
	parts := strings.Split(value, "/")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "ClamAV ") || len(value) > 256 {
		return v, ErrProtocol
	}
	v.Engine = strings.TrimPrefix(parts[0], "ClamAV ")
	if !enginePattern.MatchString(v.Engine) {
		return v, ErrProtocol
	}
	numbers := strings.Split(v.Engine, ".")
	patch, err := strconv.Atoi(numbers[2])
	if err != nil || (numbers[1] == "4" && patch < 6) || (numbers[1] == "5" && patch < 4) {
		return v, ErrProtocol
	}
	v.Database, err = strconv.ParseInt(parts[1], 10, 32)
	if err != nil || v.Database < 1 || strconv.FormatInt(v.Database, 10) != parts[1] {
		return v, ErrProtocol
	}
	if _, err = time.Parse("Mon Jan _2 15:04:05 2006", parts[2]); err != nil {
		return v, ErrProtocol
	}
	v.DatabaseDate = parts[2]
	return v, nil
}
func Validate(d Definition, now time.Time) error {
	if now.IsZero() || d.Schema != 1 || d.Kind != Backend || !filepath.IsAbs(d.Socket) || filepath.Clean(d.Socket) != d.Socket || len(d.Socket) > 100 || strings.ContainsAny(d.Socket, "\x00\r\n") || !filepath.IsAbs(d.Configuration) || filepath.Clean(d.Configuration) != d.Configuration || len(d.Configuration) > 4096 || strings.ContainsAny(d.Configuration, "\x00\r\n") || !hashPattern.MatchString(d.ConfigurationSHA256) || !d.ValidUntil.After(now) || d.ValidUntil.After(now.Add(72*time.Hour)) || d.MaxBytes < 1 || d.MaxBytes > 1<<30 || d.TimeoutSeconds < 1 || d.TimeoutSeconds > 60 || d.MaxResultAgeSeconds < 60 || d.MaxResultAgeSeconds > 3600 {
		return ErrInput
	}
	version, err := ParseVersion(d.ExpectedVersion)
	if err != nil {
		return ErrInput
	}
	// This local profile runs clamd with TZ=UTC. The protocol omits a zone;
	// deployments in another zone need a distinct, qualified profile.
	built, err := time.Parse("Mon Jan _2 15:04:05 2006", version.DatabaseDate)
	if err != nil || built.After(now.Add(5*time.Minute)) || d.ValidUntil.After(built.Add(72*time.Hour)) {
		return ErrInput
	}
	return nil
}
