"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { books } from "../lib/mock";
import BookCard from "../components/BookCard";
import GenreList from "../components/GenreList";
import BlogList from "../components/BlogList";
import BannerSlider from "../components/BannerSlider"; 
import QuickViewModal from "../components/QuickViewModal";
import { motion } from "framer-motion";

export default function Home() {
  const [isLoading, setIsLoading] = useState(true);
  const [selectedBook, setSelectedBook] = useState(null);

  useEffect(() => {
    setIsLoading(false);
  }, []);

  if (isLoading) return null;

  return (
    <section className="relative space-y-6 bg-white dark:bg-slate-900 p-3 md:p-6 rounded-xl shadow-sm border border-gray-100 dark:border-slate-800">
      
      {/* Modal Quick View */}
      <QuickViewModal book={selectedBook} onClose={() => setSelectedBook(null)} />

      {/* ================= HERO SECTION (FULL WIDTH) ================= */}
      {/* Sidebar dihapus, BannerSlider dibiarkan sendiri agar lebar penuh */}
      <motion.div 
        className="mb-4 pt-2" 
        initial={{ opacity: 0, y: 30 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.7 }}
      >
         <BannerSlider /> 
      </motion.div>

      {/* ================= GENRE LIST ================= */}
      {/* Posisinya tetap di sini (di bawah banner) */}
      <GenreList />

      {/* ================= REKOMENDASI BUKU ================= */}
      <div>
        <div className="flex items-center gap-3 mb-4 border-l-4 border-bookBlue pl-4">
          <h3 className="text-xl md:text-2xl font-serif font-bold text-slate-900 dark:text-white">
            Rekomendasi Editor
          </h3>
        </div>
        <motion.div 
          className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4" 
          initial="hidden" 
          animate="visible" 
          variants={{ 
            hidden: { opacity: 0 }, 
            visible: { opacity: 1, transition: { staggerChildren: 0.15 } } 
          }}
        >
          {books.slice(0, 4).map((b) => (
            <motion.div key={b.id} variants={{ hidden: { opacity: 0, scale: 0.9 }, visible: { opacity: 1, scale: 1 } }}>
              <BookCard book={b} onQuickView={(bookData) => setSelectedBook(bookData)} />
            </motion.div>
          ))}
        </motion.div>
      </div>

      <div className="border-t border-gray-100 dark:border-slate-800 my-6"></div>

      {/* ================= BLOG LIST ================= */}
      <BlogList />
      
    </section>
  );
}
