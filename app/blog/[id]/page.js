"use client";

import { articles } from "../../../lib/mock"; 
import Link from "next/link";
import { motion } from "framer-motion";

export default function BlogDetail({ params }) {
  // Cari artikel berdasarkan ID
  const article = articles.find((a) => a.id == params.id);

  // Tampilan jika artikel tidak ditemukan di database
  if (!article) {
    return (
        <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-4">
            <h1 className="text-4xl font-serif font-bold text-slate-800 dark:text-white mb-4">404</h1>
            <p className="text-gray-500 mb-6">Artikel tidak ditemukan di database.</p>
            <Link href="/" className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                Kembali ke Beranda
            </Link>
        </div>
    );
  }

  // Tampilan Artikel Lengkap
  return (
    <article className="max-w-3xl mx-auto py-10 px-6 sm:px-0">
      <Link href="/" className="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-blue-600 mb-8 transition-colors font-medium">
        ← Kembali ke Beranda
      </Link>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="text-center mb-10">
        <span className="inline-block px-4 py-1.5 bg-blue-50 dark:bg-slate-800 text-blue-600 dark:text-blue-400 text-xs font-bold uppercase tracking-wider rounded-full mb-6">
            {article.category}
        </span>
        <h1 className="text-3xl md:text-5xl font-serif font-bold text-slate-900 dark:text-white mb-6 leading-tight">
            {article.title}
        </h1>
        <div className="flex items-center justify-center gap-4 text-sm text-gray-500 dark:text-gray-400">
            <span>📅 {article.date}</span>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="mb-10 rounded-2xl overflow-hidden shadow-xl aspect-video bg-gray-200">
        <img src={article.image} alt={article.title} className="w-full h-full object-cover" />
      </motion.div>

      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }} 
        className="prose prose-lg dark:prose-invert max-w-none text-slate-700 dark:text-slate-300 leading-relaxed font-serif"
      >
        <div dangerouslySetInnerHTML={{ __html: article.content }} />
      </motion.div>
    </article>
  );
}
