import type { CSSProperties } from "react";

interface LoadingSpinnerProps {
  id?: string;
  /** Rotation period, as a CSS duration (e.g. "600ms"). */
  speed?: string;
  /** Diameter in pixels. The border scales with it. */
  size?: number;
  style?: CSSProperties;
}

export default function LoadingSpinner({ id, speed = "1s", size = 20, style }: LoadingSpinnerProps) {
  const borderWidth = size / 4;

  return (
    <div
      id={id}
      className="loader"
      style={{
        ...style,
        width: size,
        height: size,
        border: `${borderWidth}px solid #808080`,
        borderTop: `${borderWidth}px solid #ffffff`,
        animation: `spin ${speed} linear infinite`,
      }}
    />
  );
}
