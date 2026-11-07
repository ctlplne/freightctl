package crypto

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHDestinationAcceptsExistingCanonicalParticipantIdentity(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "client.key"), filepath.Join(dir, "client.pub")
	if err := GenerateSSHHostIdentity(private, public); err != nil {
		t.Fatal(err)
	}
	key, err := ReadSSHPublic(public)
	if err != nil {
		t.Fatal(err)
	}
	participant := NewID() + "." + NewID() + "." + NewID()
	if len(participant) != 110 {
		t.Fatal("canonical tenant.partner.actor shape changed")
	}
	d := SSHDestination{Address: "127.0.0.1:22", User: participant, Host: key, KeyFile: private, KeyFingerprint: key.Fingerprint}
	if err := ValidateSSHDestination(d); err != nil {
		t.Fatal("own canonical participant identity cannot be an outbound SFTP recipient", err)
	}
	for _, user := range []string{"receiver", "_receiver-1", strings.Repeat("a", 64)} {
		d.User = user
		if err := ValidateSSHDestination(d); err != nil {
			t.Fatal("existing short-account profile refused", err)
		}
	}
	for _, user := range []string{"", strings.Repeat("a", 65), strings.Repeat("a", 110), participant + ".", participant[:109], strings.ToUpper(participant), strings.Replace(participant, ".", "/", 1), "-receiver", "receiver\n", "réceiver"} {
		d.User = user
		if ValidateSSHDestination(d) == nil {
			t.Fatal("noncanonical or unsafe SSH account accepted")
		}
	}
	d.User, d.KeyFingerprint = participant, "SHA256:substituted"
	if ValidateSSHDestination(d) == nil {
		t.Fatal("participant name bypassed exact client key reference")
	}
	d.KeyFingerprint, d.Host.Fingerprint = key.Fingerprint, "SHA256:substituted"
	if ValidateSSHDestination(d) == nil {
		t.Fatal("participant name bypassed exact host identity")
	}
}
