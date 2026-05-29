/**
 * Shared hostname routing helpers driven by shyconfig manifests.
 */

export function resolveAppSurface(
  shyconfig,
  {
    hostname = globalThis.location?.hostname ?? "",
    allowQueryOverride = false,
    search = globalThis.location?.search ?? ""
  } = {}
) {
  const voteHost = shyconfig?.domains?.private?.vote;
  const consoleHost = shyconfig?.domains?.private?.console;

  if (
    (voteHost && hostname === voteHost) ||
    (consoleHost && hostname === consoleHost)
  ) {
    return "private";
  }

  if (allowQueryOverride) {
    const params = new URLSearchParams(search);
    if (params.has("console")) {
      return "private";
    }
  }

  return "public";
}
