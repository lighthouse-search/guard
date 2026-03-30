import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  // basePath is set by CI via NEXT_PUBLIC_BASE_PATH env var (e.g. /guard for GitHub Pages).
  // Leave blank for local dev or custom domain deployments.
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
  assetPrefix: process.env.NEXT_PUBLIC_BASE_PATH || "",
  images: {
    // next/image optimisation is unavailable in static exports
    unoptimized: true,
  },
};

export default nextConfig;
