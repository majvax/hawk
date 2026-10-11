import { type JSX, useRef } from "react";

import { type RemoteFile, type Transfer, memorySink, pickFileSink } from "../fileTransfers.js";
import type { FileActions, FilesState } from "../useDashboard.js";

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatModified(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}

const STATE_LABEL: Record<Transfer["state"], string> = {
  queued: "Queued",
  hashing: "Checking",
  waiting: "Starting",
  moving: "",
  interrupted: "Paused until the view is back",
  done: "Done",
  failed: "Failed",
  cancelled: "Cancelled",
};

function TransferRow({ transfer, actions }: { transfer: Transfer; actions: FileActions }): JSX.Element {
  const percent = transfer.size === 0 ? 100 : Math.floor((transfer.moved / transfer.size) * 100);
  const active = transfer.state !== "done" && transfer.state !== "failed" && transfer.state !== "cancelled";
  let status = STATE_LABEL[transfer.state];
  if (transfer.state === "moving") status = `${percent}%`;
  if (transfer.state === "done" && transfer.direction === "up" && transfer.savedAs !== null) {
    status = transfer.savedAs === transfer.name ? "Saved" : `Saved as ${transfer.savedAs}`;
  }
  if (transfer.state === "failed" && transfer.message !== null) status = transfer.message;
  return (
    <tr>
      <td>
        <div className="cell">
          <span className="muted" title={transfer.direction === "up" ? "To the machine" : "From the machine"}>
            {transfer.direction === "up" ? "↑" : "↓"}
          </span>
          <span className="truncate">{transfer.name}</span>
        </div>
      </td>
      <td className="num muted">{formatBytes(transfer.size)}</td>
      <td className="transfer-status">
        {transfer.state === "moving" && (
          <span className="meter" aria-hidden>
            <span style={{ width: `${percent}%` }} />
          </span>
        )}
        <span className={transfer.state === "failed" ? "warn" : "muted"}>{status}</span>
      </td>
      <td className="actions">
        {active && (
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => actions.cancel(transfer.id)}>
            Cancel
          </button>
        )}
        {transfer.state === "failed" && transfer.retryable && (
          <button type="button" className="btn btn-sm" onClick={() => actions.retry(transfer.id)}>
            Retry
          </button>
        )}
        {!active && (
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => actions.dismiss(transfer.id)}>
            Dismiss
          </button>
        )}
      </td>
    </tr>
  );
}

// Files going to and from the machine, and what's in its drop folder.
export function FilesPanel({
  files,
  actions,
  connected,
}: {
  files: FilesState;
  actions: FileActions;
  connected: boolean;
}): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);

  // The save picker has to open in the click itself, before anything is
  // awaited; where there's none, the file is assembled in memory instead.
  const download = async (file: RemoteFile): Promise<void> => {
    const picked = await pickFileSink(file.name);
    if (picked === "cancelled") return;
    actions.download(file, picked ?? memorySink(file.name));
  };

  return (
    <div className="files-panel">
      <div className="files-head">
        <span className="files-title">Files</span>
        <span className="muted truncate" title={files.listing?.dir}>
          {files.listing !== null ? files.listing.dir : "the machine's drop folder"}
        </span>
        <span className="spacer" />
        <button type="button" className="btn btn-sm btn-ghost" onClick={actions.list} disabled={!connected}>
          Refresh
        </button>
        <button type="button" className="btn btn-sm" onClick={() => inputRef.current?.click()} disabled={!connected}>
          Send files
        </button>
        <input
          ref={inputRef}
          type="file"
          multiple
          hidden
          onChange={(e) => {
            actions.upload([...(e.target.files ?? [])]);
            e.target.value = "";
          }}
        />
      </div>

      {files.transfers.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <tbody>
              {files.transfers.map((transfer) => (
                <TransferRow key={transfer.id} transfer={transfer} actions={actions} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {files.listingError !== null && <div className="empty">{files.listingError}</div>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>On the machine</th>
              <th>Size</th>
              <th>Modified</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {files.listing !== null && files.listing.files.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  Nothing here yet. Files sent to the machine land in this folder, and anything put in it can be
                  downloaded from here.
                </td>
              </tr>
            )}
            {files.listing?.files.map((file) => (
              <tr key={file.name}>
                <td>
                  <span className="truncate">{file.name}</span>
                </td>
                <td className="num muted">{formatBytes(file.size)}</td>
                <td className="num muted">{formatModified(file.modified)}</td>
                <td className="actions">
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => void download(file)}
                    disabled={!connected}
                  >
                    Download
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
