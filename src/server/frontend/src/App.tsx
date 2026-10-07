import type { JSX } from "react";

import { type ConnectionStatus, useDashboard } from "./useDashboard.js";

export function App(): JSX.Element {
  const { devices, status, viewingId, canvasRef, startView, stopView } = useDashboard();

  return (
    <main>
      <h1>Hawk Dashboard</h1>
      <p>
        Dashboard link: <StatusDot status={status} /> {status}
      </p>

      {devices.length === 0 ? (
        <p>No devices connected.</p>
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

      <section style={{ marginTop: 16, display: viewingId === null ? "none" : "block" }}>
        <h2>Live view</h2>
        <canvas
          ref={canvasRef}
          style={{ maxWidth: "100%", background: "#000", border: "1px solid #444" }}
        />
      </section>
    </main>
  );
}

function StatusDot({ status }: { status: ConnectionStatus }): JSX.Element {
  const color = status === "open" ? "limegreen" : status === "connecting" ? "orange" : "crimson";
  return (
    <span
      aria-hidden
      style={{
        display: "inline-block",
        width: 10,
        height: 10,
        borderRadius: "50%",
        background: color,
      }}
    />
  );
}
