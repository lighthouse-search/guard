"use client";

import { useState } from "react";
import TagInput from "./TagInput";

export interface HostnameData {
  active?: boolean;
  // Guard's GuardedHostname field is `host`, and it is required (not Option), so
  // the old key here produced a config Guard could not deserialize at all.
  host?: string;
  alias?: string;
  authentication_methods?: string[];
  applied_policies?: string[];
  multistep_authentication_methods?: boolean;
}

const LABEL = "text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide";
const INPUT = "rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 dark:focus:ring-zinc-500";

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative w-9 h-5 rounded-full transition-colors duration-200 shrink-0 focus:outline-none focus:ring-2 focus:ring-zinc-400 ${
        checked ? "bg-zinc-700 dark:bg-zinc-400" : "bg-zinc-200 dark:bg-zinc-700"
      }`}
    >
      <span
        className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${
          checked ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

export function HostnameFields({
  data,
  onChange,
  availableAuthMethods = [],
  availablePolicies = [],
}: {
  data: HostnameData;
  onChange: (d: HostnameData) => void;
  availableAuthMethods?: string[];
  availablePolicies?: string[];
}) {
  function update(partial: Partial<HostnameData>) {
    onChange({ ...data, ...partial });
  }

  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1.5">
          <label className={LABEL}>Hostname</label>
          <input
            value={data.host ?? ""}
            onChange={(e) => update({ host: e.target.value })}
            placeholder="app.example.com"
            className={`${INPUT}`}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className={LABEL}>
            Alias{" "}
            <span className="normal-case font-normal text-zinc-400 tracking-normal">(optional)</span>
          </label>
          <input
            value={data.alias ?? ""}
            onChange={(e) => update({ alias: e.target.value })}
            placeholder="My App"
            className={INPUT}
          />
        </div>
      </div>

      <div className="flex flex-col gap-1.5">
        <label className={LABEL}>Authentication methods</label>
        <TagInput
          tags={data.authentication_methods ?? []}
          onChange={(v) => update({ authentication_methods: v })}
          placeholder="Select or type a method…"
          suggestions={availableAuthMethods}
        />
      </div>

      <div className="flex flex-col gap-1.5">
        <div className="flex flex-col gap-0.5">
          <label className={LABEL}>Applied policies</label>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">Only users who match these policies may access this hostname. Applied policies serve as blanket access control for all traffic to a hostname.</p>
        </div>
        <TagInput
          tags={data.applied_policies ?? []}
          onChange={(v) => update({ applied_policies: v })}
          placeholder="Select or type a policy…"
          suggestions={availablePolicies}
        />
      </div>

      <label className="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={data.multistep_authentication_methods ?? false}
          onChange={(e) => update({ multistep_authentication_methods: e.target.checked })}
          className="w-4 h-4 accent-zinc-700 dark:accent-zinc-400"
        />
        <div>
          <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Multistep authentication</p>
          <p className="text-xs text-zinc-400">Require all listed methods to pass, not just one</p>
        </div>
      </label>
    </>
  );
}

interface Props {
  id: string;
  data: HostnameData;
  onChange: (id: string, data: HostnameData) => void;
  onRemove: (id: string) => void;
  availableAuthMethods?: string[];
  availablePolicies?: string[];
}

export default function HostnameComponent({ id, data, onChange, onRemove, availableAuthMethods = [], availablePolicies = [] }: Props) {
  const [expanded, setExpanded] = useState(true);
  const isActive = data.active !== false;

  function update(partial: Partial<HostnameData>) {
    onChange(id, { ...data, ...partial });
  }

  return (
    <div className={`rounded-xl border overflow-hidden transition-colors ${
      isActive
        ? "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900"
        : "border-zinc-100 dark:border-zinc-900 bg-zinc-50 dark:bg-zinc-950 opacity-60"
    }`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 text-[9px] transition-transform duration-150 shrink-0"
          style={{ transform: expanded ? "rotate(90deg)" : "rotate(0deg)" }}
          aria-label={expanded ? "Collapse" : "Expand"}
        >
          ▶
        </button>

        <div className="flex-1 min-w-0">
          <span className="text-sm font-medium text-zinc-800 dark:text-zinc-200 truncate block">
            {data.host || (
              <span className="text-zinc-400 font-sans font-normal italic">new hostname</span>
            )}
          </span>
          {data.alias && (
            <span className="text-xs text-zinc-400 truncate block">{data.alias}</span>
          )}
        </div>

        <div
          className="flex items-center gap-2 cursor-pointer select-none shrink-0"
          onClick={() => update({ active: !isActive })}
        >
          <span className="text-xs text-zinc-500">{isActive ? "Active" : "Inactive"}</span>
          <Toggle checked={isActive} onChange={() => {}} />
        </div>

        <button
          type="button"
          onClick={() => onRemove(id)}
          className="text-zinc-300 hover:text-red-400 dark:text-zinc-600 dark:hover:text-red-500 transition-colors text-xl leading-none shrink-0"
          title="Remove hostname"
        >
          ×
        </button>
      </div>

      {expanded && (
        <div className="px-4 pb-4 flex flex-col gap-4 border-t border-zinc-100 dark:border-zinc-800 pt-4">
          <HostnameFields
            data={data}
            onChange={(d) => onChange(id, d)}
            availableAuthMethods={availableAuthMethods}
            availablePolicies={availablePolicies}
          />
        </div>
      )}
    </div>
  );
}
