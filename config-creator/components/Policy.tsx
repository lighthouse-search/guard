"use client";

import { useState } from "react";

export interface PolicyData {
  active?: boolean;
  action?: "allow" | "block";
  property?: string;
  alias?: string;
  starts_with?: string;
  ends_with?: string;
}

interface Props {
  id: string;
  data: PolicyData;
  onChange: (id: string, data: PolicyData) => void;
  onRemove: (id: string) => void;
}

export default function PolicyComponent({ id, data, onChange, onRemove }: Props) {
  const [expanded, setExpanded] = useState(true);

  function update(partial: Partial<PolicyData>) {
    onChange(id, { ...data, ...partial });
  }

  const isBlock = data.action === "block";

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
      {/* Header */}
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

        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-800 dark:text-zinc-200 font-mono">
            {id}
          </span>
          <span
            className={`text-xs px-1.5 py-0.5 rounded font-medium font-sans ${
              isBlock
                ? "bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400"
                : "bg-green-50 dark:bg-green-950 text-green-600 dark:text-green-400"
            }`}
          >
            {data.action ?? "allow"}
          </span>
          {data.property && (
            <span className="text-xs text-zinc-400 truncate">
              on <code className="bg-zinc-100 dark:bg-zinc-800 px-1 rounded">{data.property}</code>
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={() => onRemove(id)}
          className="text-zinc-300 hover:text-red-400 dark:text-zinc-600 dark:hover:text-red-500 transition-colors text-xl leading-none shrink-0"
          title="Remove policy"
        >
          ×
        </button>
      </div>

      {expanded && (
        <div className="px-4 pb-4 flex flex-col gap-4 border-t border-zinc-100 dark:border-zinc-800 pt-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                Action
              </label>
              <select
                value={data.action ?? "allow"}
                onChange={(e) =>
                  update({ action: e.target.value as "allow" | "block" })
                }
                className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 outline-none focus:ring-2 focus:ring-zinc-400"
              >
                <option value="allow">Allow</option>
                <option value="block">Block</option>
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                Property
              </label>
              <input
                value={data.property ?? ""}
                onChange={(e) => update({ property: e.target.value || undefined })}
                placeholder="email"
                className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                Starts with{" "}
                <span className="normal-case font-normal text-zinc-400 tracking-normal">
                  (optional)
                </span>
              </label>
              <input
                value={data.starts_with ?? ""}
                onChange={(e) =>
                  update({ starts_with: e.target.value || undefined })
                }
                placeholder="admin."
                className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                Ends with{" "}
                <span className="normal-case font-normal text-zinc-400 tracking-normal">
                  (optional)
                </span>
              </label>
              <input
                value={data.ends_with ?? ""}
                onChange={(e) =>
                  update({ ends_with: e.target.value || undefined })
                }
                placeholder="@example.com"
                className="rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 font-mono"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
