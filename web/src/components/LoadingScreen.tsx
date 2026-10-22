import type { CSSProperties } from "react";
import Base from "@/components/Base";
import LoadingSpinner from "@/components/LoadingSpinner";

interface LoadingScreenProps {
  style?: CSSProperties;
}

/** A whole-page loading state, for before we know what to render. */
export default function LoadingScreen({ style }: LoadingScreenProps) {
  return (
    <Base style={style} className="loading_div">
      <LoadingSpinner speed="600ms" size={15} style={{ alignSelf: "center", justifySelf: "center" }} />
    </Base>
  );
}
