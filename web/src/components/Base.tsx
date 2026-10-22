import type { CSSProperties, ReactNode } from "react";
import type { LoginMetadata } from "@/types";

interface BaseProps {
  children?: ReactNode;
  className?: string;
  style?: CSSProperties;
  metadata?: LoginMetadata | null;
}

/**
 * The full-viewport page shell, plus the instance's message-of-the-day banner.
 *
 * Render this once per page: it is the element that fills the viewport, so
 * nesting it inside itself produces a duplicate MOTD banner.
 */
export default function Base({ children, className, style, metadata }: BaseProps) {
  return (
    <div className={`base ${className ?? ""}`} style={style}>
      {metadata?.motd_banner && (
        <div className="motd_banner">
          <p className="motd_banner_text">{metadata.motd_banner}</p>
        </div>
      )}
      {children}
    </div>
  );
}
