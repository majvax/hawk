import { type FormEvent, type JSX, useEffect, useState } from "react";

import {
  type ConfigSetting,
  type ConfigState,
  type SettingValue,
  changesFrom,
  checkValue,
  formatValue,
  groupByTable,
  settingName,
} from "../machineConfig.js";
import { Alert, Tag } from "../ui.js";

// How long a save (or the first load) waits for the machine to answer.
export const ANSWER_TIMEOUT_MS = 10_000;

// One setting's control, from its type alone.
function SettingControl({
  setting,
  value,
  disabled,
  onChange,
}: {
  setting: ConfigSetting;
  value: SettingValue;
  disabled: boolean;
  onChange: (value: SettingValue) => void;
}): JSX.Element {
  const id = `setting-${setting.key}`;
  switch (setting.type) {
    case "boolean":
      return (
        <label className="check">
          <input
            id={id}
            type="checkbox"
            checked={value === true}
            disabled={disabled}
            onChange={(e) => onChange(e.target.checked)}
          />
          {value === true ? "On" : "Off"}
        </label>
      );
    case "choice":
      return (
        <select
          id={id}
          className="select"
          value={String(value)}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        >
          {/* A value the file leaves unset (or one this list doesn't know) still shows. */}
          {!setting.choices.includes(String(value)) && (
            <option value={String(value)} disabled>
              {value === "" ? "(not set)" : String(value)}
            </option>
          )}
          {setting.choices.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </select>
      );
    case "integer":
      return (
        <input
          id={id}
          className="input"
          type="number"
          inputMode="numeric"
          min={setting.min}
          max={setting.max}
          step={1}
          value={typeof value === "number" && !Number.isNaN(value) ? value : ""}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value === "" ? Number.NaN : Number(e.target.value))}
        />
      );
    case "text":
      return (
        <input
          id={id}
          className="input"
          value={String(value)}
          maxLength={1024}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        />
      );
  }
}

// The machine's config, as a form generated from the schema it sends.
// `editable` is the owner, elevated; anyone else reads it.
export function ConfigPanel({
  config,
  editable,
  onSave,
}: {
  config: ConfigState;
  editable: boolean;
  onSave: (changes: Record<string, SettingValue>) => boolean;
}): JSX.Element {
  const [draft, setDraft] = useState<Record<string, SettingValue>>({});
  const [pending, setPending] = useState(false);
  // Shown once the machine says it saved; whether any of it waits for a restart.
  const [savedNeedsRestart, setSavedNeedsRestart] = useState<boolean | null>(null);
  // The relay drops a change without a word (a lapsed step-up, too many at
  // once), so a save the machine never answers gives up after a while.
  const [timedOut, setTimedOut] = useState(false);

  useEffect(() => {
    if (!pending) return;
    const timer = window.setTimeout(() => {
      setPending(false);
      setTimedOut(true);
    }, ANSWER_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [pending]);

  // Each answer from the machine settles the save waiting on it. A saved
  // change empties the form; a refused one keeps it, to fix and try again.
  useEffect(() => {
    setPending(false);
    setTimedOut(false);
    if (config.saved) setDraft({});
    else setSavedNeedsRestart(null);
  }, [config]);

  const changes = changesFrom(config.settings, draft);
  const changed = Object.keys(changes);
  const invalid = config.settings.some((setting) => {
    const value = changes[setting.key];
    return value !== undefined && checkValue(setting, value) !== null;
  });

  const save = (event: FormEvent): void => {
    event.preventDefault();
    if (changed.length === 0 || invalid || pending) return;
    const restart = config.settings.some((setting) => setting.key in changes && setting.apply === "restart");
    if (onSave(changes)) {
      setTimedOut(false);
      setPending(true);
      setSavedNeedsRestart(restart);
    }
  };

  return (
    <form className="config-form" onSubmit={save}>
      {config.error !== "" && <Alert>{config.error}</Alert>}
      {timedOut && <Alert>No answer from the machine. Try again.</Alert>}
      {config.saved && savedNeedsRestart !== null && changed.length === 0 && (
        <Alert ok>
          Saved on the machine.
          {savedNeedsRestart && " Settings marked “after restart” take effect when its service next starts."}
        </Alert>
      )}
      {!config.writable && config.settings.length > 0 && (
        <span className="field-hint">Only the machine's owner can change these.</span>
      )}

      {groupByTable(config.settings).map(([table, settings]) => (
        <div key={table} className="block">
          <span className="label">{table}</span>
          <div className="config-list">
            {settings.map((setting) => {
              const value = draft[setting.key] ?? setting.value;
              const problem = setting.key in changes ? checkValue(setting, value) : null;
              return (
                <div key={setting.key} className="config-row">
                  <label className="config-name" htmlFor={`setting-${setting.key}`}>
                    <span className="mono">{settingName(setting)}</span>
                    {setting.key in changes && <Tag tone="accent">changed</Tag>}
                    {setting.locked && (
                      <Tag title="Only someone at the machine can change this (its config's [[locked]] list)">
                        locked
                      </Tag>
                    )}
                    {setting.apply === "restart" && (
                      <Tag tone="idle" title="Takes effect when the machine's service next starts">
                        after restart
                      </Tag>
                    )}
                  </label>
                  <SettingControl
                    setting={setting}
                    value={value}
                    disabled={!editable || setting.locked || pending}
                    onChange={(next) => setDraft((current) => ({ ...current, [setting.key]: next }))}
                  />
                  <span className="field-hint">
                    {problem !== null ? (
                      <span className="warn">{problem}</span>
                    ) : (
                      <>
                        {setting.description} Default: {formatValue(setting, setting.default)}.
                      </>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ))}

      {editable && (
        <div className="form-row tight">
          <button type="submit" className="btn btn-primary" disabled={changed.length === 0 || invalid || pending}>
            {pending ? "Saving…" : changed.length > 1 ? `Save ${changed.length} changes` : "Save"}
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            disabled={changed.length === 0 || pending}
            onClick={() => setDraft({})}
          >
            Discard
          </button>
        </div>
      )}
    </form>
  );
}
