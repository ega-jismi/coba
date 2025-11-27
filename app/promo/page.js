"use client";

import { useState, useEffect, useMemo } from "react";
import BookCard from "../../components/BookCard";
import QuickViewModal from "../../components/QuickViewModal";
import { books } from "../../lib/mock";
import { motion, AnimatePresence } from "framer-motion";
import { FiClock, FiTag, FiCopy, FiCheck } from "react-icons/fi";

export default function PromoPage() {
   const [selectedBook, setSelectedBook] = useState(null);
   const [filterType, setFilterType] = useState("all"); // all, heavy, cheap
   const [copied, setCopied] = useState(false);

   // --- 1. LOGIKA COUNTDOWN TIMER ---
   const [timeLeft, setTimeLeft] = useState({ h: 0, m: 0, s: 0 });

   useEffect(() => {
      const target = new Date();
      target.setHours(23, 59, 59); // Target jam 12 malam hari ini

      const timer = setInterval(() => {
         const now = new Date();
         const diff = target - now;

         if (diff <= 0) {
            setTimeLeft({ h: 0, m: 0, s: 0 });
         } else {
            const h = Math.floor((diff / (1000 * 60 * 60)) % 24);
            const m = Math.floor((diff / 1000 / 60) % 60);
            const s = Math.floor((diff / 1000) % 60);
            setTimeLeft({ h, m, s });
         }
      }, 1000);

      return () => clearInterval(timer);
   }, []);

   // --- 2. LOGIKA COPY VOUCHER ---
   const handleCopy = () => {
      navigator.clipboard.writeText("BLOOM50");
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
   };

   // --- 3. FILTER BUKU ---
   const promoBooks = useMemo(() => {
      let filtered = books.filter((b) => b.discount && b.discount > 0);

      if (filterType === "heavy") {
         filtered = filtered.filter((b) => b.discount >= 20);
      } else if (filterType === "cheap") {
         filtered = filtered.filter((b) => {
            const finalPrice = b.price - (b.price * b.discount / 100);
            return finalPrice < 100000;
         });
      }

      return filtered;
   }, [filterType]);

   return (
      <section className="min-h-screen pb-10">
         
         {/* Modal Quick View */}
         <QuickViewModal book={selectedBook} onClose={() => setSelectedBook(null)} />

         {/* === HEADER PROMO (HERO) === */}
         <div className="relative bg-gradient-to-r from-rose-500 via-red-500 to-orange-500 rounded-2xl p-6 md:p-10 text-white shadow-lg overflow-hidden mb-10">
            
            {/* Dekorasi Background */}
            <div className="absolute top-0 right-0 w-64 h-64 bg-white/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2"></div>
            <div className="absolute bottom-0 left-0 w-40 h-40 bg-yellow-300/20 rounded-full blur-2xl translate-y-1/2 -translate-x-1/2"></div>

            <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
               
               {/* Teks & Countdown */}
               <div className="text-center md:text-left">
                  <div className="inline-flex items-center gap-2 bg-white/20 backdrop-blur-sm px-3 py-1 rounded-full text-sm font-bold mb-3 border border-white/30">
                     <FiClock /> Flash Sale Berakhir Dalam:
                  </div>
                  <div className="flex items-center justify-center md:justify-start gap-2 text-3xl md:text-5xl font-bold font-serif mb-2">
                     <span>{String(timeLeft.h).padStart(2, '0')}</span>:
                     <span>{String(timeLeft.m).padStart(2, '0')}</span>:
                     <span>{String(timeLeft.s).padStart(2, '0')}</span>
                  </div>
                  <p className="text-white/90 text-lg">Dapatkan buku impian dengan harga miring sebelum waktu habis!</p>
               </div>

               {/* Kartu Voucher */}
               <motion.div 
                  initial={{ scale: 0.9, rotate: 2 }}
                  animate={{ scale: 1, rotate: 0 }}
                  className="bg-white text-slate-900 p-5 rounded-xl shadow-2xl max-w-xs w-full border-2 border-dashed border-slate-300 relative"
               >
                  <div className="absolute -left-3 top-1/2 w-6 h-6 bg-red-500 rounded-full -translate-y-1/2"></div>
                  <div className="absolute -right-3 top-1/2 w-6 h-6 bg-orange-500 rounded-full -translate-y-1/2"></div>

                  <p className="text-xs text-slate-500 uppercase tracking-widest font-bold text-center mb-1">Kode Voucher Tambahan</p>
                  <div className="flex items-center justify-between bg-slate-100 rounded-lg p-2 border border-slate-200">
                     <span className="font-mono font-bold text-xl tracking-widest pl-2">BLOOM50</span>
                     <button 
                        onClick={handleCopy}
                        className="p-2 bg-slate-900 text-white rounded-md hover:bg-bookBlue transition-colors"
                     >
                        {copied ? <FiCheck /> : <FiCopy />}
                     </button>
                  </div>
                  <p className="text-[10px] text-center mt-2 text-slate-400">*Berlaku untuk min. belanja Rp 200rb</p>
               </motion.div>

            </div>
         </div>

         {/* === FILTER CHIPS === */}
         <div className="flex flex-wrap items-center gap-3 mb-8">
            <span className="text-slate-500 text-sm font-bold mr-2 flex items-center gap-2">
               <FiTag /> Filter Promo:
            </span>
            
            {[
               { id: "all", label: "Semua Promo" },
               { id: "heavy", label: "Diskon Besar (>20%)" },
               { id: "cheap", label: "Harga < 100rb" },
            ].map((f) => (
               <button
                  key={f.id}
                  onClick={() => setFilterType(f.id)}
                  className={`px-4 py-2 rounded-full text-sm font-bold transition-all border ${
                     filterType === f.id
                        ? "bg-red-500 text-white border-red-500 shadow-md"
                        : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-red-300"
                  }`}
               >
                  {f.label}
               </button>
            ))}
         </div>

         {/* === GRID BUKU === */}
         {promoBooks.length === 0 ? (
            <div className="text-center py-20 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-dashed border-slate-300">
               <p className="text-gray-500">Tidak ada buku yang sesuai filter promo ini.</p>
               <button onClick={() => setFilterType("all")} className="text-red-500 underline mt-2">Lihat Semua</button>
            </div>
         ) : (
            <motion.div
               layout
               className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6"
            >
               <AnimatePresence>
                  {promoBooks.map((b) => (
                     <motion.div
                        layout
                        key={b.id}
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.9 }}
                        transition={{ duration: 0.3 }}
                     >
                        <BookCard 
                           book={b} 
                           onQuickView={(data) => setSelectedBook(data)} 
                        />
                     </motion.div>
                  ))}
               </AnimatePresence>
            </motion.div>
         )}
      </section>
   );
}
