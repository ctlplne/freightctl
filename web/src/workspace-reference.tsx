import { useRef, useState } from "react";
import { asWorkspaceReference } from "./types";

export function WorkspaceReference({
  disabled,
  onSelected,
}: {
  disabled: boolean;
  onSelected: (tenant: string, partner: string) => void;
}) {
  const [message, setMessage] = useState(""),
    [failure, setFailure] = useState("");
  const selection = useRef(0);
  return (
    <div>
      <label htmlFor="workspace-reference">
        Workspace reference file (optional)
      </label>
      <input
        id="workspace-reference"
        type="file"
        accept="application/json,.json"
        disabled={disabled}
        aria-describedby="workspace-reference-help"
        onChange={async (e) => {
          const file = e.target.files?.[0],
            generation = ++selection.current;
          setMessage("");
          setFailure("");
          if (!file) return;
          try {
            if (file.size < 1 || file.size > 16384) throw new Error("size");
            const value = asWorkspaceReference(JSON.parse(await file.text()));
            if (generation !== selection.current) return;
            onSelected(value.tenant_id, value.partner_id);
            setMessage(
              "Workspace IDs loaded. Choose the account credential file to connect.",
            );
          } catch {
            if (generation === selection.current)
              setFailure(
                "Choose the workspace JSON saved by setup, at most 16 KiB, with valid tenant and partner IDs.",
              );
          }
        }}
      />
      <p id="workspace-reference-help" className="help">
        Setup saves these two IDs in its JSON result. This file fills the IDs;
        your account credential and this server still decide access.
      </p>
      {message && <p role="status">{message}</p>}
      {failure && <p role="alert">{failure}</p>}
    </div>
  );
}
