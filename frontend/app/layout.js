// import { Inter } from 'next/font/google';
// const inter = Inter({ subsets: ['latin'] })

export const metadata = {
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
      {/* className={inter.className} */}
    </html>
  )
}
