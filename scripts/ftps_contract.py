"""Shared qualification profile; execution still needs actual native clients."""

LIMITED_PARENT_TESTS = [
    "TestFTPSNativeTLSClientProtocolAndInterruption",
    "TestFTPSNativeTLSClientCredentialLifecycle",
    "TestFTPSNativeTLSClientIntakeReleaseAndRevocation",
    "TestFTPSNativeTLSClientUploadTicketRecovery",
]
NATIVE_PARENT_TESTS = LIMITED_PARENT_TESTS + [
    "TestFTPSStockCurlExplicitImplicitAndActiveCustody",
    "TestFTPSStockLFTPCustody",
    "TestFTPSStockLFTPUploadTicket",
]
NATIVE_TESTS = {name + suffix for name in NATIVE_PARENT_TESTS
                for suffix in ("", "/explicit", "/implicit")}
HOSTILE_CASE_COUNT = 15
CLI_PAYLOAD = b"exact FTPS CLI bytes\x00\r\n"
LFTP_CASES = ["epsv-exact-bytes", "pasv-exact-bytes", "active-exact-bytes", "namespace-commands"]
LFTP_DOWNLOADS = ("epsv.download", "pasv.download", "active.download", "renamed.download")
LFTP_ACTIONS = frozenset(("setup", "initial-upload", "epsv-download", "pasv-download", "active-upload", "active-download", "listing", "mkdir", "rename", "renamed-download", "remove-renamed", "remove-directory", "remove-active", "finish", "ticket-resume", "ticket-complete", "ticket-download"))
LFTP_FAILURE_CODES = {"client-unavailable", "client-deadline", "client-profile-differs",
                      "certificate-refused", "authentication-refused", "tls-transfer-refused",
                      "client-command-failed", "listing-differs", "bytes-differ", "probe-failed"}
