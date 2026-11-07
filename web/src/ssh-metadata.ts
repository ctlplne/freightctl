import { ApiError, uuid } from "./types";

// Match the existing client account profiles. Syntax supplies no authority:
// the server must still authorize the exact tenant, partner, actor and key.
export function asSSHUsername(value: unknown): string {
  if (typeof value === "string") {
    if (/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(value)) return value;
    if (value.length === 110) {
      const parts = value.split(".");
      if (parts.length === 3 && parts.every(uuid)) return value;
    }
  }
  throw new ApiError("invalid_server_response", 502);
}
