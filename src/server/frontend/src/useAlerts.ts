// Runs the threshold alerts (alerts.ts) while the dashboard is open: once a
// second, every machine with rules is checked, offline from the relay's
// word and the rest from the samples of the machine being watched (the
// only one whose numbers this browser has). What fires shows as a badge on
// the machine and a toast, and, if the user asked, as a notification from
// the browser.
import { useCallback, useEffect, useRef, useState } from "react";

import {
  ALERT_LABEL,
  type AlertKind,
  type AlertState,
  type Thresholds,
  activeKinds,
  anyEnabled,
  evaluate,
  freshReading,
  idleState,
  loadNotify,
  loadThresholds,
  needsSamples,
  saveNotify,
  saveThresholds,
} from "./alerts.js";
import type { Dashboard } from "./useDashboard.js";

export interface AlertToast {
  id: number;
  machineId: string;
  machineName: string;
  kind: AlertKind;
  fired: boolean;
  message: string;
}

export type NotifyPermission = NotificationPermission | "unsupported";

export interface Alerts {
  thresholdsFor: (machineId: string) => Thresholds;
  setThresholds: (machineId: string, thresholds: Thresholds) => void;
  // What's firing now, per machine.
  active: Record<string, AlertKind[]>;
  toasts: AlertToast[];
  dismissToast: (id: number) => void;
  // Browser notifications: whether the user turned them on here, and what
  // the browser says about them.
  notify: boolean;
  permission: NotifyPermission;
  setNotify: (on: boolean) => void;
}

const TICK_MS = 1000;
// A toast stays this long unless dismissed; the badge stays as long as the
// alert does.
const TOAST_MS = 12_000;
const MAX_TOASTS = 5;

function notificationPermission(): NotifyPermission {
  return typeof Notification === "undefined" ? "unsupported" : Notification.permission;
}

export function useAlerts(dashboard: Dashboard): Alerts {
  const { machines, viewingId, metrics, metricsActions, sparks } = dashboard;
  const [thresholds, setThresholdsState] = useState<Record<string, Thresholds>>({});
  const [active, setActive] = useState<Record<string, AlertKind[]>>({});
  const [toasts, setToasts] = useState<AlertToast[]>([]);
  const [notify, setNotifyState] = useState(loadNotify);
  const [permission, setPermission] = useState<NotifyPermission>(notificationPermission);
  const toastIdRef = useRef(0);
  const statesRef = useRef(new Map<string, AlertState>());

  // What the timer reads: the latest of everything, without restarting it.
  const latestRef = useRef({ machines, viewingId, metrics, thresholds, notify });
  latestRef.current = { machines, viewingId, metrics, thresholds, notify };

  const thresholdsFor = useCallback(
    (machineId: string): Thresholds => thresholds[machineId] ?? loadThresholds(machineId),
    [thresholds],
  );

  // Each machine's rules, read from this browser once it's in the list.
  useEffect(() => {
    const missing = machines.filter((machine) => !(machine.id in thresholds));
    if (missing.length === 0) return;
    setThresholdsState((previous) => {
      const next = { ...previous };
      for (const machine of missing) next[machine.id] ??= loadThresholds(machine.id);
      return next;
    });
  }, [machines, thresholds]);

  const setThresholds = useCallback((machineId: string, next: Thresholds): void => {
    saveThresholds(machineId, next);
    setThresholdsState((previous) => ({ ...previous, [machineId]: next }));
  }, []);

  const setNotify = useCallback((on: boolean): void => {
    if (!on) {
      saveNotify(false);
      setNotifyState(false);
      return;
    }
    if (typeof Notification === "undefined") return;
    // Asked from the click that turned it on, as browsers require.
    void Notification.requestPermission().then((answer) => {
      setPermission(answer);
      saveNotify(answer === "granted");
      setNotifyState(answer === "granted");
    });
  }, []);

  const dismissToast = useCallback((id: number): void => {
    setToasts((previous) => previous.filter((toast) => toast.id !== id));
  }, []);

  // Samples flow while a rule needs them, whatever tab is on show.
  const watched = viewingId === null ? null : (thresholds[viewingId] ?? null);
  const wantSamples = viewingId !== null && metrics.enabled && watched !== null && needsSamples(watched);
  useEffect(() => {
    if (!wantSamples) return;
    metricsActions.watch(true);
    return () => metricsActions.watch(false);
  }, [metricsActions, wantSamples, viewingId]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const { machines: list, viewingId: viewed, metrics: latest, thresholds: rules, notify: notifying } =
        latestRef.current;
      const now = Date.now();
      const states = statesRef.current;
      const fresh: AlertToast[] = [];
      const firing: Record<string, AlertKind[]> = {};
      for (const machine of list) {
        const machineRules = rules[machine.id];
        if (machineRules === undefined || !anyEnabled(machineRules)) {
          states.delete(machine.id);
          continue;
        }
        const reading =
          machine.id === viewed && latest.enabled ? freshReading(latest.latest, sparks.updatedAt(machine.id), now) : null;
        const result = evaluate(machineRules, states.get(machine.id) ?? idleState(), machine.online, reading, now);
        states.set(machine.id, result.state);
        const kinds = activeKinds(result.state);
        if (kinds.length > 0) firing[machine.id] = kinds;
        for (const transition of result.transitions) {
          toastIdRef.current += 1;
          fresh.push({ id: toastIdRef.current, machineId: machine.id, machineName: machine.name, ...transition });
          if (transition.fired && notifying && notificationPermission() === "granted") {
            try {
              new Notification(`${machine.name}: ${ALERT_LABEL[transition.kind]}`, {
                body: transition.message,
                tag: `hawk-alert-${machine.id}-${transition.kind}`,
              });
            } catch {
              // Some browsers only notify from a service worker: the toast is there.
            }
          }
        }
      }
      // Machines gone from the list take their rules' state with them.
      for (const id of states.keys()) {
        if (!list.some((machine) => machine.id === id)) states.delete(id);
      }
      setActive((previous) => (JSON.stringify(previous) === JSON.stringify(firing) ? previous : firing));
      if (fresh.length > 0) setToasts((previous) => [...previous, ...fresh].slice(-MAX_TOASTS));
    }, TICK_MS);
    return () => window.clearInterval(timer);
  }, [sparks]);

  // Toasts go by themselves after a while.
  useEffect(() => {
    if (toasts.length === 0) return;
    const oldest = toasts[0];
    if (oldest === undefined) return;
    const timer = window.setTimeout(() => dismissToast(oldest.id), TOAST_MS);
    return () => window.clearTimeout(timer);
  }, [toasts, dismissToast]);

  return { thresholdsFor, setThresholds, active, toasts, dismissToast, notify, permission, setNotify };
}
