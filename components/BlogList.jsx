"use client";

import { useRouter } from "next/navigation"; // <--- 1. Panggil useRouter
import { motion } from "framer-motion";
import { articles } from "../lib/mock"; 

export default function BlogList() {
  const router = useRouter(); // <--- 2. Inisialisasi Router

  if (!articles) return null;

  return (
    <section id="blog-section" className="py-8 mt-4">
      {/* JUDUL SECTION */}
      <div className="flex items-center justify-between mb-8 px-4 md:px-0 border-l-4 border-bookBlue ml-4 md:ml-0 pl-4">
        <div>
          <h3 className="text-2xl font-serif font-bold text-slate-900 dark:text-white">
             Wawasan & Artikel
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
             Perkaya pengetahuanmu dengan tulisan terbaru kami.
          </p>
        </div>
      </div>

      {/* GRID ARTIKEL */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {articles.map((item, i) => (
          
          <motion.article 
            key={item.id}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1 }}
            // 3. TAMBAHKAN FUNGSI KLIK DISINI
            onClick={() => router.push(`/blog/${item.id}`)}
            className="group cursor-pointer flex flex-col h-full bg-white dark:bg-slate-800 rounded-2xl overflow-hidden shadow-sm hover:shadow-xl border border-gray-100 dark:border-slate-700 transition-all duration-300"
          >
            {/* GAMBAR */}
            <div className="relative h-48 overflow-hidden bg-gray-200">
               <img 
                 // Fix gambar jika error, pakai placeholder aman
                 src={item.image || "https://images.unsplash.com/photo-1507842217121-9e9f1929c5f7?w=800&auto=format&fit=crop&q=60"} 
                 alt={item.title} 
                 className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110"
               />
               <div className="absolute top-4 left-4 bg-white/90 dark:bg-slate-900/90 backdrop-blur px-3 py-1 rounded-full text-xs font-bold text-bookBlue shadow-sm">
                 {item.category}
               </div>
            </div>

            {/* KONTEN TEKS */}
            <div className="p-6 flex flex-col flex-1">
               <div className="text-xs text-gray-400 mb-3 flex items-center gap-2">
                  <span>📅 {item.date}</span>
               </div>
               
               <h4 className="text-lg font-serif font-bold text-slate-900 dark:text-white mb-3 leading-snug group-hover:text-bookBlue transition-colors">
                 {item.title}
               </h4>
               
               <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed mb-4 flex-1 line-clamp-3">
                 {item.excerpt}
               </p>

               <div className="mt-auto pt-4 border-t border-gray-100 dark:border-slate-700">
                  <span className="text-sm font-bold text-bookBlue group-hover:underline">
                     Baca Selengkapnya →
                  </span>
               </div>
            </div>
          </motion.article>

        ))}
      </div>
    </section>
  );
}
