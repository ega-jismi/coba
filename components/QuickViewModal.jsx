"use client";

import { motion, AnimatePresence } from "framer-motion";
import { FiX, FiShoppingCart, FiCheck } from "react-icons/fi";
import useStore from "../store/store";
import { useState } from "react";

export default function QuickViewModal({ book, onClose }) {
  const addToCart = useStore((s) => s.addToCart);
  const [isAdded, setIsAdded] = useState(false);

  if (!book) return null;

  const handleAddToCart = () => {
    addToCart(book);
    setIsAdded(true);
    setTimeout(() => setIsAdded(false), 2000); // Reset tombol setelah 2 detik
  };

  // Hitung Harga Diskon (Logic sama seperti di BookCard)
  const originalPrice = Number(book.price) || 0;
  const discount = book.discount || 0;
  const finalPrice = discount > 0 
    ? originalPrice - (originalPrice * discount / 100) 
    : originalPrice;

  return (
    <AnimatePresence>
      {book && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center px-4">
          
          {/* 1. Backdrop Gelap (Klik untuk tutup) */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
          />

          {/* 2. Konten Modal */}
          <motion.div
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            className="relative w-full max-w-2xl bg-white dark:bg-slate-900 rounded-2xl shadow-2xl overflow-hidden flex flex-col md:flex-row max-h-[90vh] md:max-h-none overflow-y-auto md:overflow-visible"
          >
            
            {/* Tombol Close X */}
            <button 
              onClick={onClose}
              className="absolute top-4 right-4 z-10 p-2 bg-white/50 dark:bg-slate-800/50 hover:bg-red-100 hover:text-red-500 rounded-full transition-colors"
            >
              <FiX className="w-5 h-5" />
            </button>

            {/* Kiri: Gambar */}
            <div className="w-full md:w-1/2 bg-gray-100 dark:bg-slate-800 relative flex items-center justify-center p-6">
               <img 
                 src={book.cover} 
                 alt={book.title} 
                 className="w-auto h-64 md:h-80 object-contain shadow-lg rounded-lg"
               />
               {discount > 0 && (
                 <span className="absolute top-4 left-4 bg-red-600 text-white text-xs font-bold px-3 py-1 rounded-full">
                   Hemat {discount}%
                 </span>
               )}
            </div>

            {/* Kanan: Detail Info */}
            <div className="w-full md:w-1/2 p-6 md:p-8 flex flex-col">
               <div className="mb-1">
                 <span className="text-xs font-bold text-bookBlue uppercase tracking-wider">
                   {book.tags?.[0] || "Buku"}
                 </span>
               </div>
               
               <h2 className="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-2 leading-tight">
                 {book.title}
               </h2>
               <p className="text-sm text-gray-500 dark:text-gray-400 mb-4 border-b border-gray-100 dark:border-slate-700 pb-4">
                 Penulis: <span className="text-slate-800 dark:text-slate-200 font-medium">{book.author}</span>
               </p>

               <p className="text-sm text-gray-600 dark:text-gray-300 leading-relaxed mb-6 line-clamp-4">
                 {book.description}
               </p>

               <div className="mt-auto">
                 <div className="flex items-baseline gap-3 mb-6">
                    <span className="text-3xl font-bold text-bookOrange">
                      Rp {finalPrice.toLocaleString("id-ID")}
                    </span>
                    {discount > 0 && (
                      <span className="text-sm text-gray-400 line-through">
                        Rp {originalPrice.toLocaleString("id-ID")}
                      </span>
                    )}
                 </div>

                 <button
                    onClick={handleAddToCart}
                    disabled={isAdded}
                    className={`w-full py-3 rounded-xl font-bold text-sm flex items-center justify-center gap-2 transition-all ${
                      isAdded 
                        ? "bg-green-500 text-white"
                        : "bg-bookBlue hover:bg-blue-900 text-white shadow-lg hover:shadow-xl"
                    }`}
                 >
                    {isAdded ? (
                      <> <FiCheck className="w-5 h-5" /> Berhasil Ditambah </>
                    ) : (
                      <> <FiShoppingCart className="w-5 h-5" /> Tambah ke Keranjang </>
                    )}
                 </button>
                 
                 <div className="mt-4 text-center">
                    <a href={`/detail/${book.id}`} className="text-xs text-gray-500 hover:text-bookBlue underline">
                      Lihat Detail Selengkapnya →
                    </a>
                 </div>
               </div>
            </div>

          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
