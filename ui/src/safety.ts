const ALLOWED_DOWNLOAD_TYPES = new Set(["application/json", "text/csv"]);
const FORMULA_PREFIX = /^[=+\-@]/;

export function safeInternalUrl(value: string): string | null {
  try {
    const url = new URL(value, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/"))
      return null;
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return null;
  }
}

export function csvCell(value: string): string {
  const safe = FORMULA_PREFIX.test(value) ? `'${value}` : value;
  return `"${safe.replaceAll('"', '""')}"`;
}

export function safeFilename(value: string): string {
  const normalized = value.replaceAll(/[^a-zA-Z0-9._-]/g, "-").slice(0, 80);
  return normalized.length === 0 ? "aegis-download" : normalized;
}

export function downloadText(filename: string, mediaType: string, body: string): void {
  if (!ALLOWED_DOWNLOAD_TYPES.has(mediaType) || body.length > 1_048_576) {
    throw new Error("download violates the operator safety policy");
  }
  const blob = new Blob([body], { type: mediaType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = safeFilename(filename);
  anchor.rel = "noopener";
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function copyBoundedText(value: string): Promise<void> {
  if (value.length > 4_096) throw new Error("clipboard value exceeds its bound");
  await navigator.clipboard.writeText(value);
}

export function redactError(error: unknown): string {
  if (error instanceof Error && error.name === "ApiError") return error.message;
  return "The operator workspace failed safely. No request data was recorded.";
}
