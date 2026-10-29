package scanner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func privateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInput
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return ErrUnavailable
	}
	return nil
}

// ConfigurationCurrent verifies a protected, hash-pinned, deliberately narrow
// local deployment profile. It does not remotely attest what a hostile daemon
// loaded; the socket process and its operator remain an explicit trust boundary.
func ConfigurationCurrent(ctx context.Context, d Definition) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	secret, err := secure.ReadSecret(d.Configuration, 32<<10)
	if err != nil {
		return ErrUnavailable
	}
	defer secret.Close()
	if secure.Digest(secret.Bytes) != d.ConfigurationSHA256 || bytes.IndexByte(secret.Bytes, 0) >= 0 {
		return ErrUnavailable
	}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("Foreground LocalSocket LocalSocketMode DatabaseDirectory TemporaryDirectory PidFile MaxThreads MaxQueue StreamMaxLength MaxFileSize MaxScanSize MaxRecursion MaxFiles MaxScanTime ReadTimeout CommandReadTimeout SendBufTimeout ScanArchive ScanPE ScanELF ScanOLE2 ScanPDF ScanSWF ScanXMLDOCS ScanHWP3 ScanHTML ScanMail AlertExceedsMax AlertEncrypted AlertEncryptedArchive AlertEncryptedDoc AlertBrokenExecutables OfficialDatabaseOnly Bytecode BytecodeSecurity ConcurrentDatabaseReload SelfCheck LogTime LogClean LogVerbose DisableCache EnableVersionCommand EnableReloadCommand EnableShutdownCommand EnableStatsCommand") {
		allowed[key] = true
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(secret.Bytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 || !allowed[parts[0]] || values[parts[0]] != "" {
			return ErrInput
		}
		value := strings.TrimSpace(parts[1])
		if value == "" || strings.ContainsAny(value, "\x00\r\t#") {
			return ErrInput
		}
		values[parts[0]] = value
	}
	for _, key := range []string{"Foreground", "ScanArchive", "AlertExceedsMax", "AlertEncrypted", "OfficialDatabaseOnly", "Bytecode", "EnableVersionCommand"} {
		if strings.ToLower(values[key]) != "yes" {
			return ErrInput
		}
	}
	if values["LocalSocket"] != d.Socket || (values["LocalSocketMode"] != "600" && values["LocalSocketMode"] != "0600") || strings.ToLower(values["ConcurrentDatabaseReload"]) != "no" || values["SelfCheck"] != "0" || values["BytecodeSecurity"] != "TrustSigned" {
		return ErrInput
	}
	for _, key := range []string{"DatabaseDirectory", "TemporaryDirectory"} {
		if err := privateDirectory(values[key]); err != nil {
			return err
		}
	}
	if err := privateDirectory(filepath.Dir(d.Socket)); err != nil {
		return err
	}
	for key, bounds := range map[string][2]int64{"MaxThreads": {1, 2}, "MaxQueue": {2, 8}, "StreamMaxLength": {d.MaxBytes, 1 << 30}, "MaxFileSize": {d.MaxBytes, 1 << 30}, "MaxScanSize": {d.MaxBytes, 2 << 30}, "MaxRecursion": {1, 8}, "MaxFiles": {1, 1024}, "MaxScanTime": {1000, int64(d.TimeoutSeconds) * 1000}, "ReadTimeout": {1, int64(d.TimeoutSeconds)}, "CommandReadTimeout": {1, int64(d.TimeoutSeconds)}, "SendBufTimeout": {1, int64(d.TimeoutSeconds) * 1000}} {
		n, err := strconv.ParseInt(values[key], 10, 64)
		if err != nil || n < bounds[0] || n > bounds[1] || strconv.FormatInt(n, 10) != values[key] {
			return ErrInput
		}
	}
	for _, key := range []string{"EnableReloadCommand", "EnableShutdownCommand", "EnableStatsCommand"} {
		if strings.ToLower(values[key]) != "no" {
			return ErrInput
		}
	}
	threads, _ := strconv.Atoi(values["MaxThreads"])
	queue, _ := strconv.Atoi(values["MaxQueue"])
	if queue < 2*threads {
		return ErrInput
	}
	return ctx.Err()
}
