import type { LoginMetadata } from "@/types";

interface MetadataPanelProps {
  metadata: LoginMetadata | null;
}

/**
 * The branding panel beside the login form: the instance's background image,
 * logo, name and description.
 *
 * Purely presentational — the screen that owns the page fetches metadata once
 * and passes it down. (It used to fetch its own copy, which both duplicated the
 * request and threw on pages that have no `?redirect=` to resolve a host from.)
 */
export default function MetadataPanel({ metadata }: MetadataPanelProps) {
  // This value goes straight into a CSS url(), so parse it first: anything that
  // is not a real URL must not reach the stylesheet.
  let image: string | null = null;
  if (metadata?.image) {
    try {
      image = new URL(metadata.image, window.location.origin).href;
    } catch {
      // Not a usable URL — fall through to the plain background colour.
    }
  }

  return (
    <div
      className="aesthetic_metadata_panel_left"
      style={{
        backgroundImage: image ? `url(${image})` : undefined,
        backgroundColor: image ? undefined : "#000000",
      }}
    >
      {metadata && (
        <div className="aesthetic_metadata_panel_left_div">
          {metadata.logo && <img className="max-w-[140px] max-h-[80px] mb-1" src={metadata.logo} alt="" />}
          {metadata.alias && <h2 className="text-white text-2xl font-semibold">{metadata.alias}</h2>}
          <p className="text-white text-base">{metadata.public_description}</p>
        </div>
      )}
    </div>
  );
}
