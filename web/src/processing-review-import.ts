import { ApiError, type Session } from "./types";
import {
  parseReviewRecovery,
  type ReviewMutation,
} from "./processing-review-api";

export async function importReviewRecoveryFile({
  file,
  session,
  origin,
  current,
  busy,
  prepare,
}: {
  file: Pick<File, "size" | "text">;
  session: Session;
  origin: string;
  current: () => boolean;
  busy: () => boolean;
  prepare: (mutation: ReviewMutation) => Promise<void>;
}): Promise<void> {
  if (
    !Number.isSafeInteger(file.size) ||
    file.size < 0 ||
    file.size > 32 * 1024
  )
    throw new ApiError("invalid_processing_review", 400);
  if (!current()) throw new ApiError("session_changed", 403);
  const text = await file.text();
  if (!current()) throw new ApiError("session_changed", 403);
  const mutation = parseReviewRecovery(text, session, origin);
  // File selection can finish after a background inspection starts. Always
  // validate the untrusted file,then explicitly refuse concurrent preparation.
  // There is no await between this check and prepare's synchronous lock entry.
  if (busy()) throw new ApiError("review_inspection_busy", 409);
  await prepare(mutation);
}
