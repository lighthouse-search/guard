"use client";

import { useState } from "react";

interface TagInputProps {
  tags: string[];
  onChange: (tags: string[]) => void;
  placeholder?: string;
}

export default function TagInput({ tags, onChange, placeholder }: TagInputProps) {
  const [input, setInput] = useState("");

  function addTag() {
    const trimmed = input.trim().replace(/,+$/, "");
    if (trimmed && !tags.includes(trimmed)) {
      onChange([...tags, trimmed]);
    }
    setInput("");
  }

  return (
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
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            addTag();
          }
          if (e.key === "Backspace" && input === "" && tags.length > 0) {
            onChange(tags.slice(0, -1));
          }
        }}
        onBlur={() => { if (input.trim()) addTag(); }}
        placeholder={tags.length === 0 ? (placeholder ?? "Type and press Enter…") : ""}
        className="flex-1 min-w-[100px] text-sm outline-none bg-transparent text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400"
      />
    </div>
  );
}
