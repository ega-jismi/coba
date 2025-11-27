import '../styles/globals.css'
import Navbar from '../components/Navbar'
import Footer from '../components/Footer'
// 1. IMPORT FONT DARI GOOGLE
import { Merriweather, Roboto } from 'next/font/google'

// 2. KONFIGURASI FONT SERIF (UNTUK JUDUL)
const merriweather = Merriweather({
  subsets: ['latin'],
  weight: ['300', '400', '700', '900'], // Ambil variasi ketebalan
  variable: '--font-merriweather',      // Nama variabel CSS
  display: 'swap',
})

// 3. KONFIGURASI FONT SANS (UNTUK NAVIGASI & TEKS BIASA)
const roboto = Roboto({
  subsets: ['latin'],
  weight: ['300', '400', '500', '700'],
  variable: '--font-roboto',
  display: 'swap',
})

export const metadata = {
  title: 'Paper Bloom | Toko Buku Online',
  description: 'Temukan ribuan buku terbaik untuk wawasanmu.'
}

export default function RootLayout({ children }){
  return (
    // 4. MASUKKAN KEDUA VARIABEL KE HTML
    <html lang="id" className={`${merriweather.variable} ${roboto.variable}`}>
      <body className="min-h-screen flex flex-col font-sans bg-gray-50 text-gray-900 dark:bg-slate-900 dark:text-gray-100 transition-colors duration-300">
        <Navbar />
        <main className="flex-1 container max-w-screen-xl mx-auto px-4 py-8">
          {children}
        </main>
        <Footer />
      </body>
    </html>
  )
}
