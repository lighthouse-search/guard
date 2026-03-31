"use client";

import { QuickstartPreset, QUICKSTART_PRESETS } from "./quickstartPresets";

interface Props {
  onSelect: (preset: QuickstartPreset) => void;
  onSkip: () => void;
}

export default function Quickstart({ onSelect, onSkip }: Props) {
  return (
    <div className="flex flex-col items-center justify-center bg-zinc-50 dark:bg-zinc-950 h-screen font-sans px-6">
      <div className="w-full max-w-lg flex flex-col gap-8">
        {/* Heading */}
        <div className="flex flex-col gap-1.5">
          <h1 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
            Guard config creator
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            How would you like users to authenticate?
          </p>
        </div>

        {/* Preset cards */}
        <div className="flex flex-col gap-2">
          {QUICKSTART_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => onSelect(preset)}
              className="flex items-center gap-4 px-4 py-3.5 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-zinc-400 dark:hover:border-zinc-600 hover:shadow-sm transition-all text-left group"
            >
              <span className="shrink-0 text-zinc-500 dark:text-zinc-400 group-hover:text-zinc-700 dark:group-hover:text-zinc-200 transition-colors">
                {preset.icon}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
                  {preset.label}
                </p>
                <p className="text-xs text-zinc-400 mt-0.5">{preset.description}</p>
              </div>
              <span className="text-zinc-300 dark:text-zinc-600 group-hover:text-zinc-400 dark:group-hover:text-zinc-400 text-lg leading-none transition-colors">
                →
              </span>
            </button>
          ))}
        </div>

        {/* Skip */}
        <div className="flex justify-center">
          <button
            type="button"
            onClick={onSkip}
            className="text-sm text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors"
          >
            Start from scratch
          </button>
        </div>
      </div>
    </div>
  );
}
