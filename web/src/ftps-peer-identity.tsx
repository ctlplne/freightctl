import type { FTPSConnectionProof } from "./ftps-metadata";

export function FTPSPeerIdentity({ proof }: { proof: FTPSConnectionProof }) {
  return (
    <>
      {proof.mode} FTPS; TLS certificate name <code>{proof.server_name}</code>,
      trusted CA bundle SHA-256 <code>{proof.ca_sha256}</code>.
    </>
  );
}

export function FTPSReceiverTerms({ proof }: { proof: FTPSConnectionProof }) {
  return (
    <>
      Receiver-private staging <code>{proof.staging_directory}</code>. The
      receiver may replace the final name and must deduplicate the delivery ID.
      The sender checks exact readback. The receipt does not acknowledge
      receiver fsync or business acceptance. A missing reply blocks automatic
      resend. Receiver contract{" "}
      <code>{proof.receiver_contract.document_sha256}</code>.
    </>
  );
}
