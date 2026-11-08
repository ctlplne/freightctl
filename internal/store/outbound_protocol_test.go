package store

import "testing"

func TestDispatchReviewSchemaCannotAcquireAnotherProtocolCapability(t *testing.T) {
	profiles := []OutboundDispatchEffect{{Protocol: "sftp"}, {Protocol: "ftps", FTPS: &OutboundFTPSEffect{}}, {Protocol: "webdav", DAV: &OutboundDAVEffect{}}}
	for i, profile := range profiles {
		for schema := 1; schema <= 3; schema++ {
			if validOutboundDispatchProtocol(schema, profile) != (schema == i+1) {
				t.Fatal("dispatch review schema and protocol capability diverged")
			}
		}
	}
	for _, bad := range []OutboundDispatchEffect{{Protocol: "webdav"}, {Protocol: "webdav", DAV: &OutboundDAVEffect{}, FTPS: &OutboundFTPSEffect{}}, {Protocol: "webdav", DAV: &OutboundDAVEffect{}, Workflow: &ExecutionBinding{}}, {Protocol: "webdav", DAV: &OutboundDAVEffect{}, Encryption: &EncryptionPolicy{}}, {Protocol: "sftp", DAV: &OutboundDAVEffect{}}, {Protocol: "unknown"}} {
		for schema := 1; schema <= 3; schema++ {
			if validOutboundDispatchProtocol(schema, bad) {
				t.Fatal("mixed or unknown capability acquired dispatch authority")
			}
		}
	}
}
