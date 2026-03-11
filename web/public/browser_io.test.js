import { describe, expect, it, vi } from "vitest";
import {
  readResponseBytesWithLimit,
  validateUploadSizes,
} from "./browser_io.js";

describe("readResponseBytesWithLimit", () => {
  it("rejects oversized responses before arrayBuffer buffering when Content-Length is too large", async () => {
    const controller = { abort: vi.fn() };
    const arrayBuffer = vi.fn();
    const resp = {
      headers: new Headers({ "Content-Length": "1048577" }),
      body: null,
      arrayBuffer,
    };

    await expect(
      readResponseBytesWithLimit(resp, {
        maxBytes: 1024 * 1024,
        controller,
      }),
    ).rejects.toThrow(/too large/);

    expect(controller.abort).toHaveBeenCalledTimes(1);
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it("rejects oversized streamed responses once the byte limit is exceeded", async () => {
    const controller = { abort: vi.fn() };
    const resp = new Response(
      new ReadableStream({
        start(streamController) {
          streamController.enqueue(new Uint8Array([1, 2, 3]));
          streamController.enqueue(new Uint8Array([4, 5]));
          streamController.close();
        },
      }),
      { status: 200 },
    );

    await expect(
      readResponseBytesWithLimit(resp, { maxBytes: 4, controller }),
    ).rejects.toThrow(/too large/);

    expect(controller.abort).toHaveBeenCalledTimes(1);
  });

  it("returns bytes for bounded streamed responses", async () => {
    const resp = new Response(
      new ReadableStream({
        start(streamController) {
          streamController.enqueue(new Uint8Array([1, 2]));
          streamController.enqueue(new Uint8Array([3, 4]));
          streamController.close();
        },
      }),
      { status: 200 },
    );

    const got = await readResponseBytesWithLimit(resp, { maxBytes: 8 });
    expect(Array.from(got)).toEqual([1, 2, 3, 4]);
  });
});

describe("validateUploadSizes", () => {
  it("rejects files above the per-file limit", () => {
    const msg = validateUploadSizes([
      { name: "huge.p12", size: 10 * 1024 * 1024 + 1 },
    ]);
    expect(msg).toBe("huge.p12 is too large (max 10 MB per file).");
  });

  it("rejects batches above the total limit", () => {
    const msg = validateUploadSizes([
      { name: "one.pem", size: 9 * 1024 * 1024 },
      { name: "two.pem", size: 9 * 1024 * 1024 },
      { name: "three.pem", size: 9 * 1024 * 1024 },
      { name: "four.pem", size: 9 * 1024 * 1024 },
      { name: "five.pem", size: 9 * 1024 * 1024 },
      { name: "six.pem", size: 9 * 1024 * 1024 },
    ]);
    expect(msg).toBe("Selected files are too large (max 50 MB total).");
  });

  it("formats override limits in user-facing messages", () => {
    const msg = validateUploadSizes([{ name: "huge.pem", size: 2049 }], {
      maxFileBytes: 2048,
      maxTotalBytes: 4096,
    });
    expect(msg).toBe("huge.pem is too large (max 2048 bytes per file).");
  });

  it("accepts bounded uploads", () => {
    const msg = validateUploadSizes([
      { name: "leaf.pem", size: 1024 },
      { name: "chain.pem", size: 2048 },
    ]);
    expect(msg).toBe("");
  });
});
