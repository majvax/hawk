// File transfer, the dashboard's side (src/service/files.hpp has the
// machine's, and the message table). Uploads are hashed first, then sent in
// a window of chunks the machine acknowledges; downloads are written as they
// arrive and acknowledged once written. Either kind that a dropped
// connection interrupts picks up where it stopped once the view is back:
// the machine keeps a partial upload, and a download asks for the rest.

import { fromBase64, toBase64 } from "./crypto.js";
import { Sha256 } from "./sha256.js";

export const FILE_OP = {
  list: 1,
  offer: 2,
  chunk: 3,
  fetch: 4,
  ack: 5,
  cancel: 6,
  listing: 17,
  accepted: 18,
  progress: 19,
  done: 20,
  meta: 21,
  data: 22,
  error: 23,
} as const;

const CHUNK_SIZE = 64 * 1024;
const WINDOW_CHUNKS = 8;
// What the machine allows each way per viewer; more wait their turn here.
const MAX_ACTIVE = 2;
const HASH_SLICE = 4 * 1024 * 1024;

export interface RemoteFile {
  name: string;
  size: number;
  modified: number; // unix seconds
}

export interface Listing {
  dir: string;
  files: RemoteFile[];
}

export type TransferState =
  | "queued" // waiting for a free slot
  | "hashing" // reading the file to hash it before offering it
  | "waiting" // asked the machine, no answer yet
  | "moving" // data on its way
  | "interrupted" // the view dropped; resumes when it's back
  | "done"
  | "failed"
  | "cancelled";

export interface Transfer {
  id: string;
  direction: "up" | "down";
  name: string;
  size: number;
  moved: number; // bytes acknowledged (up) or written (down)
  state: TransferState;
  message: string | null; // why it failed
  // Whether a failed transfer can pick up where it stopped: not once what
  // was downloaded so far had to be thrown away.
  retryable: boolean;
  savedAs: string | null; // up: the name the machine gave it
}

// Where a download is written: a file the viewer picked (streamed to disk),
// or memory, handed over as a regular download at the end.
export interface Sink {
  write(data: Uint8Array<ArrayBuffer>): Promise<void>;
  close(): Promise<void>;
  abort(): void;
}

// Sends one sealed file-channel message; false when there's no view to
// send it on.
export type FileSender = (op: number, header: object, data?: Uint8Array) => boolean;

interface Upload extends Transfer {
  direction: "up";
  file: File;
  sha256: string | null;
  next: number; // the next offset to send
  reading: boolean;
}

interface Download extends Transfer {
  direction: "down";
  sink: Sink;
  hash: Sha256;
  sha256: string | null; // as the machine first said
  expected: number; // the offset of the next chunk to accept
  writes: Promise<void>;
}

type Active = Upload | Download;

interface ReplyHeader {
  id?: string;
  offset?: number;
  received?: number;
  size?: number;
  name?: string;
  sha256?: string;
  message?: string;
}

function isListing(header: unknown): header is Listing {
  return typeof header === "object" && header !== null && Array.isArray((header as Listing).files);
}

export class FileManager {
  listing: Listing | null = null;
  listingError: string | null = null;
  private readonly transfers = new Map<string, Active>();
  private sender: FileSender | null = null;

  constructor(private readonly onChange: () => void) {}

  // What the view's state is: a sender while it's secured, null once it
  // isn't. Interrupted transfers resume when one comes back.
  attach(sender: FileSender | null): void {
    this.sender = sender;
    for (const transfer of this.transfers.values()) {
      if (sender === null && (transfer.state === "waiting" || transfer.state === "moving")) {
        transfer.state = "interrupted";
      }
    }
    if (sender !== null) {
      for (const transfer of this.transfers.values()) {
        if (transfer.state === "interrupted") transfer.state = "queued";
      }
      this.schedule();
    }
    this.onChange();
  }

  list(): void {
    this.listingError = null;
    this.send(FILE_OP.list, {});
  }

  snapshot(): Transfer[] {
    return [...this.transfers.values()].map(
      ({ id, direction, name, size, moved, state, message, retryable, savedAs }): Transfer => ({
        id,
        direction,
        name,
        size,
        moved,
        state,
        message,
        retryable,
        savedAs,
      }),
    );
  }

  upload(file: File): void {
    const id = crypto.randomUUID();
    this.transfers.set(id, {
      id,
      direction: "up",
      name: file.name,
      size: file.size,
      moved: 0,
      state: "queued",
      message: null,
      retryable: true,
      savedAs: null,
      file,
      sha256: null,
      next: 0,
      reading: false,
    });
    this.schedule();
    this.onChange();
  }

  download(file: RemoteFile, sink: Sink): void {
    const id = crypto.randomUUID();
    this.transfers.set(id, {
      id,
      direction: "down",
      name: file.name,
      size: file.size,
      moved: 0,
      state: "queued",
      message: null,
      retryable: true,
      savedAs: null,
      sink,
      hash: new Sha256(),
      sha256: null,
      expected: 0,
      writes: Promise.resolve(),
    });
    this.schedule();
    this.onChange();
  }

  cancel(id: string): void {
    const transfer = this.transfers.get(id);
    if (transfer === undefined || transfer.state === "done") return;
    if (transfer.state === "waiting" || transfer.state === "moving") this.send(FILE_OP.cancel, { id });
    if (transfer.direction === "down") transfer.sink.abort();
    transfer.state = "cancelled";
    this.schedule();
    this.onChange();
  }

  retry(id: string): void {
    const transfer = this.transfers.get(id);
    if (transfer?.state !== "failed" || !transfer.retryable) return;
    transfer.state = "queued";
    transfer.message = null;
    this.schedule();
    this.onChange();
  }

  dismiss(id: string): void {
    const transfer = this.transfers.get(id);
    if (transfer === undefined) return;
    if (transfer.state !== "done" && transfer.state !== "failed" && transfer.state !== "cancelled") return;
    if (transfer.state === "failed" && transfer.direction === "down") transfer.sink.abort();
    this.transfers.delete(id);
    this.onChange();
  }

  // Everything still going is given up on (the view moved to another
  // machine, or closed).
  close(): void {
    for (const transfer of this.transfers.values()) {
      if (transfer.direction === "down" && transfer.state !== "done") transfer.sink.abort();
    }
    this.transfers.clear();
    this.sender = null;
  }

  // One opened message from the machine.
  handle(op: number, rawHeader: unknown, data: Uint8Array<ArrayBuffer>): void {
    if (op === FILE_OP.listing) {
      if (isListing(rawHeader)) this.listing = rawHeader;
      this.onChange();
      return;
    }
    const header = (typeof rawHeader === "object" && rawHeader !== null ? rawHeader : {}) as ReplyHeader;
    if (op === FILE_OP.error && (header.id === undefined || header.id === "")) {
      this.listingError = header.message ?? "the machine couldn't list its files";
      this.onChange();
      return;
    }
    const transfer = this.transfers.get(header.id ?? "");
    if (transfer === undefined || transfer.state === "cancelled") return;
    if (op === FILE_OP.error) {
      this.fail(transfer, header.message ?? "the machine refused");
    } else if (transfer.direction === "up") {
      this.handleUpload(transfer, op, header);
    } else {
      this.handleDownload(transfer, op, header, data);
    }
    this.onChange();
  }

  // --- internals -----------------------------------------------------------------

  private send(op: number, header: object, data?: Uint8Array): boolean {
    return this.sender?.(op, header, data) ?? false;
  }

  private fail(transfer: Active, message: string, retryable = true): void {
    transfer.state = "failed";
    transfer.message = message;
    transfer.retryable = retryable;
    if (!retryable && transfer.direction === "down") transfer.sink.abort();
    this.schedule();
  }

  // Starts queued transfers while there are free slots.
  private schedule(): void {
    if (this.sender === null) return;
    for (const direction of ["up", "down"] as const) {
      const busy = [...this.transfers.values()].filter(
        (transfer) =>
          transfer.direction === direction &&
          (transfer.state === "hashing" || transfer.state === "waiting" || transfer.state === "moving"),
      ).length;
      let free = MAX_ACTIVE - busy;
      for (const transfer of this.transfers.values()) {
        if (free <= 0) break;
        if (transfer.direction !== direction || transfer.state !== "queued") continue;
        free -= 1;
        if (transfer.direction === "up") void this.startUpload(transfer);
        else this.startDownload(transfer);
      }
    }
  }

  private async startUpload(upload: Upload): Promise<void> {
    if (upload.sha256 === null) {
      upload.state = "hashing";
      this.onChange();
      try {
        const hash = new Sha256();
        for (let offset = 0; offset < upload.file.size; offset += HASH_SLICE) {
          hash.update(new Uint8Array(await upload.file.slice(offset, offset + HASH_SLICE).arrayBuffer()));
          if (upload.state !== "hashing") return; // cancelled meanwhile
        }
        upload.sha256 = toBase64(hash.digest());
      } catch {
        this.fail(upload, "couldn't read the file");
        this.onChange();
        return;
      }
    }
    upload.state = "waiting";
    if (!this.send(FILE_OP.offer, { id: upload.id, name: upload.name, size: upload.size, sha256: upload.sha256 })) {
      upload.state = "interrupted";
    }
    this.onChange();
  }

  private handleUpload(upload: Upload, op: number, header: ReplyHeader): void {
    if (op === FILE_OP.accepted) {
      upload.next = header.offset ?? 0;
      upload.moved = upload.next;
      upload.state = "moving";
      void this.pumpUpload(upload);
    } else if (op === FILE_OP.progress) {
      upload.moved = Math.max(upload.moved, header.received ?? 0);
      void this.pumpUpload(upload);
    } else if (op === FILE_OP.done) {
      upload.state = "done";
      upload.moved = upload.size;
      upload.savedAs = header.name ?? upload.name;
      this.schedule();
    }
  }

  // Sends chunks while the window has room. One read at a time, so chunks
  // are sealed (and so sent) in order.
  private async pumpUpload(upload: Upload): Promise<void> {
    if (upload.reading) return;
    upload.reading = true;
    try {
      while (
        upload.state === "moving" &&
        upload.next < upload.size &&
        upload.next - upload.moved < WINDOW_CHUNKS * CHUNK_SIZE
      ) {
        const offset = upload.next;
        const data = new Uint8Array(await upload.file.slice(offset, offset + CHUNK_SIZE).arrayBuffer());
        if (upload.state !== "moving" || upload.next !== offset) return;
        if (!this.send(FILE_OP.chunk, { id: upload.id, offset }, data)) {
          upload.state = "interrupted";
          this.onChange();
          return;
        }
        upload.next = offset + data.length;
      }
    } catch {
      this.fail(upload, "couldn't read the file");
      this.onChange();
    } finally {
      upload.reading = false;
    }
  }

  private startDownload(download: Download): void {
    download.state = "waiting";
    download.expected = download.moved;
    if (!this.send(FILE_OP.fetch, { id: download.id, name: download.name, offset: download.moved })) {
      download.state = "interrupted";
    }
  }

  private handleDownload(download: Download, op: number, header: ReplyHeader, data: Uint8Array<ArrayBuffer>): void {
    if (op === FILE_OP.meta) {
      if (download.sha256 !== null && header.sha256 !== download.sha256) {
        this.fail(download, "the file changed on the machine; download it again", false);
        return;
      }
      download.sha256 = header.sha256 ?? null;
      download.size = header.size ?? download.size;
      download.state = "moving";
      if (download.expected === download.size) this.queueWrite(download, null);
    } else if (op === FILE_OP.data) {
      // Anything but the next chunk is a leftover from before a retry.
      if (download.state !== "moving" || header.offset !== download.expected) return;
      download.expected += data.length;
      this.queueWrite(download, data);
    }
  }

  // Writes (and hashes) a chunk after the ones before it, acknowledges it,
  // and finishes the download after its last one.
  private queueWrite(download: Download, data: Uint8Array<ArrayBuffer> | null): void {
    download.writes = download.writes.then(async () => {
      if (download.state !== "moving") return;
      if (data !== null) {
        try {
          await download.sink.write(data);
        } catch {
          this.fail(download, "couldn't write the file here", false);
          this.send(FILE_OP.cancel, { id: download.id });
          this.onChange();
          return;
        }
        download.hash.update(data);
        download.moved += data.length;
        this.send(FILE_OP.ack, { id: download.id, received: download.moved });
      }
      if (download.moved === download.size) await this.finishDownload(download);
      this.onChange();
    });
  }

  private async finishDownload(download: Download): Promise<void> {
    const digest = download.hash.digest();
    const expected = download.sha256 === null ? null : fromBase64(download.sha256);
    const intact = expected !== null && expected.length === digest.length && expected.every((b, i) => b === digest[i]);
    if (!intact) {
      this.fail(download, "the file didn't arrive intact; download it again", false);
      return;
    }
    try {
      await download.sink.close();
      download.state = "done";
    } catch {
      this.fail(download, "couldn't save the file", false);
    }
    this.schedule();
  }
}

// What the File System Access API hands back, where there is one.
interface WritableFile {
  write: (data: Uint8Array) => Promise<void>;
  close: () => Promise<void>;
  abort: () => Promise<void>;
}
type SavePicker = (options: { suggestedName: string }) => Promise<{ createWritable: () => Promise<WritableFile> }>;

// A download written straight to a file the viewer picks, where the browser
// can (Chromium); null if it can't, "cancelled" if the viewer closed the
// picker.
export async function pickFileSink(name: string): Promise<Sink | "cancelled" | null> {
  const picker = (window as Window & { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
  if (picker === undefined) return null;
  let handle;
  try {
    handle = await picker({ suggestedName: name });
  } catch (error) {
    return error instanceof DOMException && error.name === "AbortError" ? "cancelled" : null;
  }
  const writable = await handle.createWritable();
  return {
    write: (data) => writable.write(data),
    close: () => writable.close(),
    abort: () => void writable.abort().catch(() => {}),
  };
}

// A download kept in memory and handed to the browser as a regular download
// once complete.
export function memorySink(name: string): Sink {
  let parts: Uint8Array<ArrayBuffer>[] = [];
  return {
    write: (data) => {
      parts.push(data);
      return Promise.resolve();
    },
    close: () => {
      const url = URL.createObjectURL(new Blob(parts));
      parts = [];
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      return Promise.resolve();
    },
    abort: () => {
      parts = [];
    },
  };
}
