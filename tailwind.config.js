/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
 
    // Jika kamu punya folder 'src', tambahkan juga baris di bawah ini:
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: 'class', // Penting agar fitur Dark Mode kamu berfungsi
  theme: {
    extend: {
      colors: {
        // Menambahkan warna custom sesuai project kamu (saya ambil dari penggunaan di komponen)
        bookBlue: '#0ea5e9', // Sesuaikan kode hex jika perlu (ini contoh default sky-500)
        bookOrange: '#f97316',
        bookRed: '#ef4444',
      },
      fontFamily: {
        serif: ['var(--font-merriweather)'],
        sans: ['var(--font-roboto)'],
      },
    },
  },
  plugins: [],
}
