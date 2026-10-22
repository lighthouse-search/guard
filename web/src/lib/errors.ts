/**
 * Turn anything thrown into a message fit for the UI.
 *
 * Failures arrive in three shapes here: the client library throws the server's
 * error object (`{ error: true, message }`), the browser throws `Error`, and
 * some of our own guards throw plain strings.
 */
export function errorMessage(cause: unknown, fallback = "Something went wrong."): string {
  if (typeof cause === "string") {
    return cause;
  }

  if (cause && typeof cause === "object" && "message" in cause) {
    const { message } = cause as { message?: unknown };
    if (typeof message === "string" && message.length > 0) {
      return message;
    }
  }

  return fallback;
}
