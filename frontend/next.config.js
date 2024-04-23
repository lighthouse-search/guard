/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'export',
    distDir: '_static',
    images: {
        unoptimized: true
    },
    trailingSlash: true,
    basePath: '/frontend'
}

module.exports = nextConfig
