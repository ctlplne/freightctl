import type { CheckView } from "./types";

export function CheckEvidence({ view }: { view: CheckView }) {
  const proof = view.signatureProof;
  return (
    <>
      {(view.validation?.code === "valid_csv" ||
        view.validation?.code === "valid_json_records") && (
        <dl className="facts" aria-label="Recorded validation result">
          <dt>Rows checked</dt>
          <dd>{view.validation.rows.toLocaleString()}</dd>
          <dt>Bytes checked</dt>
          <dd>{view.validation.bytes.toLocaleString()}</dd>
        </dl>
      )}
      {proof && (
        <div className="signature-box">
          <h3>Recorded signature verification</h3>
          <p>
            The primary fingerprint identifies the signer selected by policy.
            The signing key may be an authorized subkey. Compare these full
            fingerprints with your approved partner record.
          </p>
          <dl className="facts">
            <dt>Verified primary signer</dt>
            <dd>
              <code>{proof.primary}</code>
            </dd>
            <dt>Verified signing key</dt>
            <dd>
              <code>{proof.signer}</code>
            </dd>
            <dt>Registered key</dt>
            <dd>
              <code>{proof.keyID}</code> · version {proof.keyVersion}
            </dd>
            <dt>Key policy SHA-256</dt>
            <dd>
              <code>{proof.keyHash}</code>
            </dd>
            <dt>Signature SHA-256</dt>
            <dd>
              <code>{proof.signatureSHA256}</code>
            </dd>
            <dt>Signature format and digest</dt>
            <dd>
              OpenPGP v{proof.signatureVersion} · {proof.hashAlgorithm}
            </dd>
            <dt>Signature created</dt>
            <dd>
              <time dateTime={proof.createdAt}>{proof.createdAt}</time>
            </dd>
            <dt>Verification recorded</dt>
            <dd>
              <time dateTime={proof.verifiedAt}>{proof.verifiedAt}</time>
            </dd>
            <dt>Verification window ends</dt>
            <dd>
              {proof.validUntil ? (
                <time dateTime={proof.validUntil}>{proof.validUntil}</time>
              ) : (
                "No fixed end in this recorded proof"
              )}
            </dd>
          </dl>
          <p>
            These are the recorded check results. The server rechecks current
            access, signer trust, expiry and exact bytes before release and
            retrieval.
          </p>
        </div>
      )}
    </>
  );
}
