import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import MetadataPanel from "@/components/MetadataPanel";
import type { LoginMetadata } from "@/types";

interface MetadataPanelFrameProps {
  children?: ReactNode;
  metadata?: LoginMetadata | null;
}

/** Below this width the branding panel collapses and its image moves behind the form. */
const NARROW_BREAKPOINT = 808;

/**
 * The split login layout: branding on the left, the form on the right.
 *
 * Render inside a `Base` — this is the inner layout, not the page shell.
 */
export default function MetadataPanelFrame({ children, metadata = null }: MetadataPanelFrameProps) {
  const [isNarrow, setIsNarrow] = useState(false);

  useEffect(() => {
    function handleResize() {
      setIsNarrow(window.innerWidth < NARROW_BREAKPOINT);
    }

    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // Parsed rather than interpolated: this value is written into a CSS url().
  let narrowBackground: string | undefined;
  if (isNarrow && metadata?.image) {
    try {
      narrowBackground = `url(${new URL(metadata.image).href})`;
    } catch {
      // Not a usable URL — no background.
    }
  }

  return (
    <div className="aesthetic_metadata_panel_frame">
      <MetadataPanel metadata={metadata} />

      <div className="line">.</div>

      <div className="aesthetic_metadata_panel_right" style={{ backgroundImage: narrowBackground }}>
        {children}
      </div>
    </div>
  );
}
