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

module.exports = nextConfig
