/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'export',
    distDir: '_static',
    images: {
        unoptimized: true
    },
    trailingSlash: true,
    basePath: '/guard/frontend'
}

export default nextConfig
