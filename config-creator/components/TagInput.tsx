"use client";

import { useState } from "react";

interface TagInputProps {
  tags: string[];
  onChange: (tags: string[]) => void;
  placeholder?: string;
  suggestions?: string[];
}

export default function TagInput({ tags, onChange, placeholder, suggestions = [] }: TagInputProps) {
  const [input, setInput] = useState("");
  const [open, setOpen] = useState(false);

  const filtered = suggestions.filter(
    (s) => !tags.includes(s) && s.toLowerCase().includes(input.toLowerCase())
  );

  function addTag(value: string) {
    const trimmed = value.trim().replace(/,+$/, "");
    if (trimmed && !tags.includes(trimmed)) {
      onChange([...tags, trimmed]);
    }
    setInput("");
  }

  return (
    <div className="relative">
      <div className="flex flex-wrap gap-1.5 items-center min-h-[38px] rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-2 py-1.5 focus-within:ring-2 focus-within:ring-zinc-400 dark:focus-within:ring-zinc-500 transition-shadow">
        {tags.map((tag) => (
          <span
            key={tag}
            className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs px-2 py-0.5 rounded-full"
          >
            {tag}
            <button
              type="button"
              onClick={() => onChange(tags.filter((t) => t !== tag))}
              className="text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-100 leading-none ml-0.5 text-base"
            >
              ×
            </button>
          </span>
        ))}
        <input
          value={input}
          onChange={(e) => { setInput(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              addTag(input);
            }
            if (e.key === "Escape") setOpen(false);
            if (e.key === "Backspace" && input === "" && tags.length > 0) {
              onChange(tags.slice(0, -1));
            }
          }}
          placeholder={tags.length === 0 ? (placeholder ?? "Type and press Enter…") : ""}
          className="flex-1 min-w-[100px] text-sm outline-none bg-transparent text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400"
        />
      </div>

      {open && filtered.length > 0 && (
        <div className="absolute z-20 top-full left-0 right-0 mt-1 rounded-md border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 shadow-lg overflow-hidden max-h-48 overflow-y-auto">
          {filtered.map((s) => (
            <button
              key={s}
              type="button"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => { addTag(s); setOpen(true); }}
              className="w-full px-3 py-1.5 text-sm text-left text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 font-mono"
            >
              {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
