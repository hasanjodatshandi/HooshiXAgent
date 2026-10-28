import { ApiError } from "@/lib/api";
import type { Messages } from "@/lib/i18n";

export function apiErrorMessage(error: unknown, messages: Messages): string {
  if (error instanceof ApiError) {
    if (error.status === 401 || error.status === 403) {
      return messages.errors.unauthorizedTitle;
    }
    if (error.status === 502 || error.status === 504) {
      return messages.errors.serverUnavailable;
    }
    if (error.message.trim()) return error.message.trim();
  }
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  return messages.errors.unknown;
}
