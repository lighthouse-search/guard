import type { CSSProperties, KeyboardEvent, ChangeEvent, HTMLInputTypeAttribute } from "react";

interface LabelledInputProps {
  id?: string;
  header: string;
  placeholder?: string;
  value?: string;
  onChange?: (event: ChangeEvent<HTMLInputElement>) => void;
  onKeyDown?: (event: KeyboardEvent<HTMLInputElement>) => void;
  style?: CSSProperties;
  type?: HTMLInputTypeAttribute;
  autoCapitalize?: string;
  className?: string;
}

/** A text input with a label above it. */
export default function LabelledInput({
  id,
  header,
  placeholder,
  value,
  onChange,
  onKeyDown,
  style,
  type,
  autoCapitalize,
  className,
}: LabelledInputProps) {
  return (
    <div id={id} className="input_with_header">
      <p className="input_with_header_headertxt">{header}</p>
      <input
        placeholder={placeholder}
        // Always a string: passing null/undefined to a controlled input makes
        // React warn and silently switch the field to uncontrolled.
        value={value ?? ""}
        onChange={onChange}
        onKeyDown={onKeyDown}
        style={style}
        type={type}
        autoCapitalize={autoCapitalize}
        className={`input_with_header_input ${className ?? ""}`}
      />
    </div>
  );
}
