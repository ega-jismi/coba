export default function Footer() {
   return (
      <footer className="mt-12 border-t border-gray-100 dark:border-slate-800 bg-white dark:bg-slate-900 transition-colors duration-300">
         <div className="container py-8 text-center text-sm text-gray-500 dark:text-gray-400 font-serif">
            {/* === PERUBAHAN NAMA DISINI === */}
            © {new Date().getFullYear()} Paper Bloom — Toko Buku Online Terlengkap. All rights reserved.
         </div>
      </footer>
   );
}
