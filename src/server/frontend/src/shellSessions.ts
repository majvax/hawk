// Shells on the machine, the dashboard's side (src/service/shell.hpp has
// the machine's, and the message table). Output is acknowledged once the
// terminal has written it, which is what keeps the machine sending: it holds
// back past 256 KB unacknowledged. A shell doesn't outlive its view: the
// machine closes it when the viewer leaves, so a dropped connection ends it.

export const SHELL_OP = {
  open: 1,
  input: 2,
  resize: 3,
  ack: 4,
  close: 5,
  opened: 17,
  output: 18,
  exited: 19,
  error: 20,
} as const;

// The most bytes of input in one message; a large paste goes in several.
const INPUT_CHUNK = 16 * 1024;

export type ShellState = "opening" | "open" | "exited" | "failed";

export interface ShellInfo {
  id: string;
  title: string;
  state: ShellState;
  code: number | null; // the exit code, once exited
  message: string | null; // why it failed, or ended
}

// Where a shell's output goes: the terminal showing it. `written` is called
// once the terminal has taken the bytes.
export type OutputSink = (data: Uint8Array, written: () => void) => void;

export type ShellSender = (op: number, header: object, data?: Uint8Array) => boolean;

interface Shell extends ShellInfo {
  received: number; // output bytes the terminal has written
  expected: number; // the offset of the next output chunk
  pending: Uint8Array[]; // output that arrived before a terminal was attached
  sink: OutputSink | null;
}

interface ReplyHeader {
  id?: string;
  offset?: number;
  code?: number;
  message?: string;
}

export class ShellManager {
  private readonly shells = new Map<string, Shell>();
  private sender: ShellSender | null = null;
  private opened = 0;

  constructor(private readonly onChange: () => void) {}

  // A sender while the view is secured, null once it isn't. Without a view
  // the machine has closed every shell, so they're shown as ended.
  attach(sender: ShellSender | null): void {
    this.sender = sender;
    if (sender === null) {
      for (const shell of this.shells.values()) {
        if (shell.state === "opening" || shell.state === "open") {
          shell.state = "exited";
          shell.message = "the connection to the machine dropped";
        }
      }
    }
    this.onChange();
  }

  get connected(): boolean {
    return this.sender !== null;
  }

  snapshot(): ShellInfo[] {
    return [...this.shells.values()].map(({ id, title, state, code, message }) => ({ id, title, state, code, message }));
  }

  // Opens a shell of `cols` x `rows`; returns its id, or null with no view.
  open(cols: number, rows: number): string | null {
    if (this.sender === null) return null;
    const id = crypto.randomUUID();
    this.opened += 1;
    this.shells.set(id, {
      id,
      title: `Shell ${this.opened}`,
      state: "opening",
      code: null,
      message: null,
      received: 0,
      expected: 0,
      pending: [],
      sink: null,
    });
    if (!this.send(SHELL_OP.open, { id, cols, rows })) this.shells.delete(id);
    this.onChange();
    return this.shells.has(id) ? id : null;
  }

  input(id: string, text: string): void {
    if (this.shells.get(id)?.state !== "open") return;
    const bytes = new TextEncoder().encode(text);
    for (let offset = 0; offset < bytes.length; offset += INPUT_CHUNK) {
      this.send(SHELL_OP.input, { id }, bytes.subarray(offset, offset + INPUT_CHUNK));
    }
  }

  resize(id: string, cols: number, rows: number): void {
    const state = this.shells.get(id)?.state;
    if (state === "open" || state === "opening") this.send(SHELL_OP.resize, { id, cols, rows });
  }

  // Closes it on the machine (killing what it started) and forgets it.
  close(id: string): void {
    const shell = this.shells.get(id);
    if (shell === undefined) return;
    if (shell.state === "open" || shell.state === "opening") this.send(SHELL_OP.close, { id });
    this.shells.delete(id);
    this.onChange();
  }

  // The terminal showing this shell, or null when it goes away. Output
  // that arrived meanwhile is written to the new one first.
  setSink(id: string, sink: OutputSink | null): void {
    const shell = this.shells.get(id);
    if (shell === undefined) return;
    shell.sink = sink;
    if (sink === null) return;
    const pending = shell.pending;
    shell.pending = [];
    for (const data of pending) this.deliver(shell, data);
  }

  // Everything is dropped: the view moved to another machine, or closed.
  closeAll(): void {
    for (const id of [...this.shells.keys()]) this.close(id);
    this.sender = null;
  }

  handle(op: number, rawHeader: unknown, data: Uint8Array): void {
    const header = (typeof rawHeader === "object" && rawHeader !== null ? rawHeader : {}) as ReplyHeader;
    const shell = this.shells.get(header.id ?? "");
    if (shell === undefined) return;
    if (op === SHELL_OP.opened) {
      shell.state = "open";
    } else if (op === SHELL_OP.output) {
      // Anything but the next chunk would garble the screen; it can't
      // happen with an honest relay, which never reorders a queue.
      if (header.offset !== shell.expected) return;
      shell.expected += data.length;
      if (shell.sink === null) shell.pending.push(data);
      else this.deliver(shell, data);
      return; // nothing the panel shows changed
    } else if (op === SHELL_OP.exited) {
      shell.state = "exited";
      shell.code = header.code ?? null;
    } else if (op === SHELL_OP.error) {
      shell.state = shell.state === "opening" ? "failed" : "exited";
      shell.message = header.message ?? "the machine refused";
    }
    this.onChange();
  }

  private deliver(shell: Shell, data: Uint8Array): void {
    shell.sink?.(data, () => {
      shell.received += data.length;
      if (shell.state === "open") this.send(SHELL_OP.ack, { id: shell.id, received: shell.received });
    });
  }

  private send(op: number, header: object, data?: Uint8Array): boolean {
    return this.sender?.(op, header, data) ?? false;
  }
}
