const MB = 1024 * 1024;

export const MAX_AIA_RESPONSE_BYTES = 1 * MB;
export const MAX_UPLOAD_FILE_BYTES = 10 * MB;
export const MAX_UPLOAD_TOTAL_BYTES = 50 * MB;

function tooLargeError(actualBytes, maxBytes) {
  return new Error(
    `AIA response too large (${actualBytes} bytes, max ${maxBytes})`,
  );
}

function parseContentLength(headers) {
  const raw = headers?.get?.("Content-Length");
  if (!raw) {
    return null;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return null;
  }
  return parsed;
}

export async function readResponseBytesWithLimit(
  resp,
  { maxBytes = MAX_AIA_RESPONSE_BYTES, controller = null } = {},
) {
  const declaredLength = parseContentLength(resp.headers);
  if (declaredLength !== null && declaredLength > maxBytes) {
    controller?.abort();
    throw tooLargeError(declaredLength, maxBytes);
  }

  if (!resp.body || typeof resp.body.getReader !== "function") {
    const body = await resp.arrayBuffer();
    if (body.byteLength > maxBytes) {
      controller?.abort();
      throw tooLargeError(body.byteLength, maxBytes);
    }
    return new Uint8Array(body);
  }

  const reader = resp.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value || value.byteLength === 0) {
        continue;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        controller?.abort();
        try {
          await reader.cancel("response too large");
        } catch {
          // Ignore cancellation errors; the size violation is the root cause.
        }
        throw tooLargeError(total, maxBytes);
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Ignore release failures from already-closed streams.
    }
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export function validateUploadSizes(
  files,
  {
    maxFileBytes = MAX_UPLOAD_FILE_BYTES,
    maxTotalBytes = MAX_UPLOAD_TOTAL_BYTES,
  } = {},
) {
  let totalBytes = 0;
  for (const file of files) {
    const size = Number(file?.size ?? 0);
    const name = file?.name || "file";
    if (!Number.isFinite(size) || size < 0) {
      return `Could not determine size for ${name}.`;
    }
    if (size > maxFileBytes) {
      return `${name} is too large (max 10 MB per file).`;
    }
    totalBytes += size;
    if (totalBytes > maxTotalBytes) {
      return "Selected files are too large (max 50 MB total).";
    }
  }
  return "";
}
