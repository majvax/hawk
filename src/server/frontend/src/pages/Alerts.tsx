// Alerts on the page: the dialog that sets a machine's thresholds, the badge
// on a machine that has one firing, and the toasts that say so as it
// happens. The rules and their evaluation are alerts.ts and useAlerts.ts.
import { type FormEvent, type JSX, useEffect, useRef, useState } from "react";

import { ALERT_LABEL, type AlertKind, type Thresholds, anyEnabled } from "../alerts.js";
import type { Machine } from "../protocol.js";
import type { AlertToast, Alerts } from "../useAlerts.js";
import { Corners, Tag } from "../ui.js";

// "Alert" on a machine with rules firing, naming them on hover.
export function AlertBadge({ kinds }: { kinds: AlertKind[] | undefined }): JSX.Element | null {
  if (kinds === undefined || kinds.length === 0) return null;
  const names = kinds.map((kind) => ALERT_LABEL[kind]).join(", ");
  // The toasts announce it as it fires; this says what's still on.
  return (
    <Tag tone="err" solid title={names}>
      {kinds.length === 1 ? `Alert: ${names}` : `${kinds.length} alerts`}
    </Tag>
  );
}

// The latest alerts as they fire and clear, bottom right.
export function AlertToasts({
  toasts,
  onDismiss,
  onOpen,
}: {
  toasts: AlertToast[];
  onDismiss: (id: number) => void;
  onOpen: (machineId: string) => void;
}): JSX.Element {
  return (
    <div className="toasts" role="log" aria-live="polite" aria-label="Alerts">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast ${toast.fired ? "tone-err" : "tone-ok"}`}>
          <button type="button" className="toast-body" onClick={() => onOpen(toast.machineId)}>
            <span className="toast-title">
              {toast.machineName} · {ALERT_LABEL[toast.kind]}
              {!toast.fired && " · cleared"}
            </span>
            <span>{toast.message}</span>
          </button>
          <button type="button" className="toast-close" aria-label="Dismiss" onClick={() => onDismiss(toast.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

// A number field that reads as one: a bad entry keeps the last good value.
function NumberField({
  label,
  value,
  min,
  max,
  unit,
  disabled,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  unit: string;
  disabled: boolean;
  onChange: (value: number) => void;
}): JSX.Element {
  return (
    <label className="alert-number">
      <span className="sr-only">{label}</span>
      <input
        className="input"
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        value={value}
        disabled={disabled}
        onChange={(event) => {
          const next = Number(event.target.value);
          if (event.target.value !== "" && Number.isFinite(next)) onChange(Math.min(max, Math.max(min, next)));
        }}
      />
      <span className="muted">{unit}</span>
    </label>
  );
}

// The thresholds of one machine, for this browser.
export function AlertsDialog({
  machine,
  alerts,
  onClose,
}: {
  machine: Machine;
  alerts: Alerts;
  onClose: () => void;
}): JSX.Element {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [draft, setDraft] = useState<Thresholds>(() => alerts.thresholdsFor(machine.id));
  const samples = machine.role === "owner" || machine.analytics === true;

  useEffect(() => {
    dialogRef.current?.showModal();
  }, []);

  const save = (event: FormEvent): void => {
    event.preventDefault();
    alerts.setThresholds(machine.id, draft);
    onClose();
  };

  const rule = <K extends keyof Thresholds>(kind: K, patch: Partial<Thresholds[K]>): void =>
    setDraft((previous) => ({ ...previous, [kind]: { ...previous[kind], ...patch } }));

  const toggle = (kind: keyof Thresholds, label: string, disabled = false): JSX.Element => (
    <label className="check">
      <input
        type="checkbox"
        checked={draft[kind].enabled}
        disabled={disabled}
        onChange={(event) => rule(kind, { enabled: event.target.checked })}
      />
      {label}
    </label>
  );

  return (
    <dialog
      ref={dialogRef}
      className="dialog"
      aria-labelledby="alerts-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <form className="auth-panel alerts-panel" onSubmit={save}>
        <Corners />
        <h1 id="alerts-title">Alerts for {machine.name}</h1>
        <p className="prose muted">
          Checked by this browser while the dashboard is open: the machine's numbers are end-to-end encrypted, so the
          relay can't watch them for you. CPU, memory, disk and temperature are checked while you're connected to the
          machine{samples ? "" : ", and need a share with analytics"}; offline, for every machine.
        </p>
        <div className="alert-rules">
          <div className="alert-rule">
            {toggle("cpu", "CPU over", !samples)}
            <NumberField
              label="CPU percent"
              value={draft.cpu.percent}
              min={1}
              max={100}
              unit="%"
              disabled={!samples || !draft.cpu.enabled}
              onChange={(percent) => rule("cpu", { percent })}
            />
            <span className="muted">for</span>
            <NumberField
              label="CPU seconds"
              value={draft.cpu.seconds}
              min={1}
              max={3600}
              unit="s"
              disabled={!samples || !draft.cpu.enabled}
              onChange={(seconds) => rule("cpu", { seconds })}
            />
          </div>
          <div className="alert-rule">
            {toggle("memory", "Memory over", !samples)}
            <NumberField
              label="Memory percent"
              value={draft.memory.percent}
              min={1}
              max={100}
              unit="%"
              disabled={!samples || !draft.memory.enabled}
              onChange={(percent) => rule("memory", { percent })}
            />
          </div>
          <div className="alert-rule">
            {toggle("disk", "A drive's free space under", !samples)}
            <NumberField
              label="Free space percent"
              value={draft.disk.percent}
              min={1}
              max={99}
              unit="%"
              disabled={!samples || !draft.disk.enabled}
              onChange={(percent) => rule("disk", { percent })}
            />
          </div>
          <div className="alert-rule">
            {toggle("temperature", "Temperature over", !samples)}
            <NumberField
              label="Temperature in degrees Celsius"
              value={draft.temperature.celsius}
              min={20}
              max={130}
              unit="°C"
              disabled={!samples || !draft.temperature.enabled}
              onChange={(celsius) => rule("temperature", { celsius })}
            />
          </div>
          <div className="alert-rule">
            {toggle("offline", "Offline for")}
            <NumberField
              label="Offline seconds"
              value={draft.offline.seconds}
              min={10}
              max={86_400}
              unit="s"
              disabled={!draft.offline.enabled}
              onChange={(seconds) => rule("offline", { seconds })}
            />
          </div>
        </div>
        <div className="alert-notify">
          <label className="check">
            <input
              type="checkbox"
              checked={alerts.notify}
              disabled={alerts.permission === "unsupported" || alerts.permission === "denied"}
              onChange={(event) => alerts.setNotify(event.target.checked)}
            />
            Also as browser notifications
          </label>
          <span className="field-hint">
            {alerts.permission === "unsupported"
              ? "This browser doesn't do notifications."
              : alerts.permission === "denied"
                ? "Blocked for this site in the browser's settings."
                : "For every machine, from this browser. Only while the dashboard is open."}
          </span>
        </div>
        <div className="form-row tight">
          <button type="submit" className="btn btn-primary">
            {anyEnabled(draft) ? "Save" : "Save, all off"}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}
