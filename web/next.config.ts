import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Guard serves the frontend as pre-built static files (see the static file
  // handler in server/src/main.rs), so there is no Node runtime in the
  // container — everything here must export statically.
  output: "export",
  distDir: "_static",
  images: {
    unoptimized: true,
  },
  // The Rust server mounts the frontend under this prefix and links to
  // /guard/frontend/login and /guard/frontend/magiclink directly, so page
  // routes and this basePath have to stay in sync with the server.
  basePath: "/guard/frontend",
  allowedDevOrigins: ['127.0.0.1'],
};

export default nextConfig;
