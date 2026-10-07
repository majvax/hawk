import type { JSX } from "react";

import { useDevices } from "./useDevices.js";

export function App(): JSX.Element {
  const { devices, status } = useDevices();

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
            </tr>
          </thead>
          <tbody>
            {devices.map((device) => (
              <tr key={device.id}>
                <td>{device.machineId}</td>
                <td>{new Date(device.connectedAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}

function StatusDot({ status }: { status: "connecting" | "open" | "closed" }): JSX.Element {
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
