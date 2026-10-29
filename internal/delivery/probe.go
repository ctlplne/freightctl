package delivery

import (
	"context"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// ProbeSFTP negotiates/authenticates and traverses an already registered path.
// It never lists names, opens payloads, writes, renames or removes remote data.
func ProbeSFTP(ctx context.Context, destination secure.SSHDestination, directory string) store.OnboardingProbeObservation {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	o := store.OnboardingProbeObservation{Code: "connection_failed"}
	client, stream, err := connect(ctx, &Definition{Destination: destination})
	if err != nil {
		if ctx.Err() != nil {
			o.Code = "probe_deadline_exceeded"
		}
		return o
	}
	defer stream.Close()
	defer client.Close()
	o.SSH, o.SFTP = true, true
	for _, name := range []string{"fsync@openssh.com", "hardlink@openssh.com"} {
		if version, ok := client.HasExtension(name); !ok || version != "1" {
			o.Code = "required_extensions_missing"
			return o
		}
	}
	o.Extensions = true
	if remoteDirectory(client, directory) != nil {
		o.Code = "directory_unavailable"
		if ctx.Err() != nil {
			o.Code = "probe_deadline_exceeded"
		}
		return o
	}
	o.Directory = true
	o.Code = "connectivity_verified"
	return o
}
