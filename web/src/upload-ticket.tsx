import type { Upload } from "./types";

export function UploadTicket({ upload }: { upload: Upload }) {
  return (
    <section aria-label="Saved upload details">
      <dl className="facts">
        <dt>Upload state</dt>
        <dd>{upload.state}</dd>
        <dt>Expected bytes</dt>
        <dd>{upload.expected_size}</dd>
        <dt>Committed bytes</dt>
        <dd>{upload.committed_offset}</dd>
        <dt>Expected SHA-256</dt>
        <dd>
          <code>{upload.expected_sha256}</code>
        </dd>
        {upload.sftp_path && (
          <>
            <dt>SFTP transfer path</dt>
            <dd>
              <code>{upload.sftp_path}</code>
            </dd>
          </>
        )}
        {upload.ftps_path && (
          <>
            <dt>FTPS transfer path</dt>
            <dd>
              <code>{upload.ftps_path}</code>
            </dd>
          </>
        )}
        {upload.file_id && (
          <>
            <dt>Accepted file ID</dt>
            <dd>
              <code>{upload.file_id}</code>
            </dd>
          </>
        )}
        {upload.acceptance && (
          <>
            <dt>Acceptance</dt>
            <dd>
              {upload.acceptance === "durable-held-pending-checks-and-release"
                ? "Accepted and held for checks and release"
                : upload.acceptance}
            </dd>
          </>
        )}
      </dl>
      {upload.state === "open" && (upload.sftp_path || upload.ftps_path) && (
        <p className="help">
          Send the original complete file to its transfer path using your
          enrolled account and verified server identity. FTPS requires binary
          mode. After interruption, read the committed position and send the
          remaining bytes. Bytes after that position may need to be sent again.
          A full progress bar alone does not mean acceptance.
        </p>
      )}
      {upload.state === "completed" && (
        <p className="help">
          This is the server’s saved acceptance record, including its original
          file ID. If a transfer reply was lost, inspect this record before
          sending again. Required checks and release still control retrieval;
          acceptance does not prove delivery to a recipient.
        </p>
      )}
    </section>
  );
}
