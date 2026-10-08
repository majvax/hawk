import type { JSX } from "react";

import { type ConnectionStatus, useDashboard } from "../useDashboard.js";

export function MachinesPage({ onSocketClosed }: { onSocketClosed: () => void }): JSX.Element {
  const { devices, status, viewingId, canvasRef, startView, stopView } = useDashboard(onSocketClosed);

  return (
    <div className="stack">
      <p className="muted">
        <StatusDot status={status} /> relay link {status}
      </p>

      {devices.length === 0 ? (
        <p className="muted">No machines connected.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Machine</th>
              <th>Connected since</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {devices.map((device) => (
              <tr key={device.id}>
                <td>{device.machineId}</td>
                <td>{new Date(device.connectedAt).toLocaleString()}</td>
                <td>
                  {viewingId === device.id ? (
                    <button type="button" onClick={stopView}>
                      Stop
                    </button>
                  ) : (
                    <button type="button" onClick={() => startView(device.id)}>
                      View
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <section style={{ display: viewingId === null ? "none" : "block" }}>
        <h2>Live view</h2>
        <canvas ref={canvasRef} className="screen" />
      </section>
    </div>
  );
}

function StatusDot({ status }: { status: ConnectionStatus }): JSX.Element {
  return <span aria-hidden className={`dot dot-${status}`} />;
}
