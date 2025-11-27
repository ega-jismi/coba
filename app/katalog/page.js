"use client";

import { useMemo, useState, useEffect } from "react"; // Tambah useEffect
import BookCard from "../../components/BookCard";
import QuickViewModal from "../../components/QuickViewModal"; 
import { books } from "../../lib/mock";
import useStore from "../../store/store";
import { motion } from "framer-motion";
import { FiFilter, FiChevronDown, FiSearch, FiX } from "react-icons/fi";

export default function Katalog() {
   const q = useStore((s) => s.query);
   const setQuery = useStore((s) => s.setQuery);
   
   // --- AMBIL STATE GLOBAL DARI STORE ---
   const selectedCategory = useStore((s) => s.selectedCategory);
   const setSelectedCategory = useStore((s) => s.setSelectedCategory);
   // -------------------------------------

   const [selectedPriceId, setSelectedPriceId] = useState("all");
   const [sortBy, setSortBy] = useState("newest"); 
   const [selectedBook, setSelectedBook] = useState(null); 

   // Reset filter saat halaman pertama kali dimuat (Opsional, jika ingin selalu reset)
   // Tapi karena kita ingin fitur klik dari home jalan, jangan di-reset di useEffect []

   const categories = ["All", "Business", "Finance", "Startup", "Design", "Poetry", "Self-help"];

   const priceRanges = [
      { id: "all", label: "Semua Harga" },
      { id: "under_100", label: "< Rp 100.000", min: 0, max: 100000 },
      { id: "100_150", label: "Rp 100rb - 150rb", min: 100000, max: 150000 },
      { id: "150_200", label: "Rp 150rb - 200rb", min: 150000, max: 200000 },
      { id: "above_200", label: "> Rp 200.000", min: 200001, max: Infinity },
   ];

   // --- LOGIKA UTAMA (FILTERING) ---
   const filteredBooks = useMemo(() => {
      return books.filter((b) => {
         
         // 1. Filter Pencarian
         const matchQuery = b.title.toLowerCase().includes(q.toLowerCase()) || 
                            b.author.toLowerCase().includes(q.toLowerCase()) ||
                            b.tags.some(tag => tag.toLowerCase().includes(q.toLowerCase()));
         
         // 2. Filter Kategori (Sekarang pakai Global State)
         const matchCategory = selectedCategory === "All" || 
                               b.tags.some(tag => tag.toLowerCase() === selectedCategory.toLowerCase());

         // 3. Filter Harga
         let matchPrice = true;
         if (selectedPriceId !== "all") {
            const range = priceRanges.find(r => r.id === selectedPriceId);
            if (range) {
               matchPrice = b.price >= range.min && b.price <= range.max;
            }
         }

         return matchQuery && matchCategory && matchPrice;

      }).sort((a, b) => {
         if (sortBy === "low-high") return a.price - b.price;
         if (sortBy === "high-low") return b.price - a.price;
         return 0; 
      });
   }, [q, selectedCategory, selectedPriceId, sortBy]);

   // Fungsi Reset
   const handleReset = () => {
      setQuery("");
      setSelectedCategory("All"); // Reset ke Global State
      setSelectedPriceId("all");
      setSortBy("newest");
   };

   return (
      <section className="min-h-screen">
         <QuickViewModal book={selectedBook} onClose={() => setSelectedBook(null)} />

         {/* HEADER KATALOG */}
         <div className="bg-white dark:bg-slate-800 p-6 rounded-xl border border-gray-200 dark:border-slate-700 mb-8 shadow-sm">
            <h1 className="text-3xl font-serif font-bold text-slate-900 dark:text-white mb-2">Katalog Buku</h1>
            <p className="text-slate-500 dark:text-slate-400 text-sm">Temukan koleksi terbaik untuk menambah wawasanmu.</p>
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            
            {/* --- SIDEBAR FILTER (KIRI) --- */}
            <div className="lg:col-span-1 space-y-6">
               
               {/* Filter Kategori */}
               <div className="bg-white dark:bg-slate-800 p-5 rounded-xl border border-gray-200 dark:border-slate-700 shadow-sm">
                  <div className="flex justify-between items-center mb-4">
                     <h3 className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <FiFilter /> Kategori
                     </h3>
                     {(selectedCategory !== "All" || selectedPriceId !== "all") && (
                        <button onClick={handleReset} className="text-xs text-red-500 hover:underline">Reset</button>
                     )}
                  </div>
                  
                  <div className="flex flex-col gap-2">
                     {categories.map((cat) => (
                        <button
                           key={cat}
                           onClick={() => setSelectedCategory(cat)}
                           className={`text-left px-3 py-2 rounded-lg text-sm font-medium transition-all flex justify-between items-center ${
                              selectedCategory === cat 
                                 ? "bg-bookBlue text-white shadow-md" 
                                 : "text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
                           }`}
                        >
                           {cat}
                           {selectedCategory === cat && <span className="text-xs">✓</span>}
                        </button>
                     ))}
                  </div>
               </div>

               {/* Filter Harga */}
               <div className="bg-white dark:bg-slate-800 p-5 rounded-xl border border-gray-200 dark:border-slate-700 shadow-sm">
                  <h3 className="font-bold text-slate-900 dark:text-white mb-4">Range Harga</h3>
                  <div className="flex flex-col gap-2">
                     {priceRanges.map((range) => (
                        <button
                           key={range.id}
                           onClick={() => setSelectedPriceId(range.id)}
                           className={`text-left px-3 py-2 rounded-lg text-sm font-medium transition-all border ${
                              selectedPriceId === range.id
                                 ? "bg-orange-50 dark:bg-orange-900/20 border-bookOrange text-bookOrange font-bold" 
                                 : "border-transparent text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
                           }`}
                        >
                           {range.label}
                        </button>
                     ))}
                  </div>
               </div>
            </div>

            {/* --- KONTEN UTAMA (KANAN) --- */}
            <div className="lg:col-span-3">
               
               {/* Kontrol Atas */}
               <div className="flex flex-col sm:flex-row justify-between items-center mb-6 gap-4 bg-white dark:bg-slate-800 p-4 rounded-xl border border-gray-200 dark:border-slate-700 shadow-sm">
                  <div className="text-slate-600 dark:text-slate-300 text-sm flex flex-wrap gap-2 items-center">
                     <span>Menampilkan <strong>{filteredBooks.length}</strong> buku</span>
                     {q && (
                        <span className="bg-blue-100 dark:bg-blue-900 text-bookBlue px-2 py-0.5 rounded-full text-xs flex items-center gap-1">
                           Pencarian: "{q}" 
                           <button onClick={() => setQuery("")} className="hover:text-red-500 ml-1">✕</button>
                        </span>
                     )}
                     {/* INDIKATOR KATEGORI AKTIF */}
                     {selectedCategory !== "All" && (
                        <span className="bg-orange-100 dark:bg-orange-900 text-bookOrange px-2 py-0.5 rounded-full text-xs flex items-center gap-1">
                           Kategori: "{selectedCategory}"
                           <button onClick={() => setSelectedCategory("All")} className="hover:text-red-500 ml-1">✕</button>
                        </span>
                     )}
                  </div>

                  <div className="flex items-center gap-3">
                     <span className="text-sm text-slate-500">Urutkan:</span>
                     <div className="relative">
                        <select 
                           value={sortBy}
                           onChange={(e) => setSortBy(e.target.value)}
                           className="appearance-none pl-4 pr-10 py-2 bg-slate-50 dark:bg-slate-900 border border-gray-200 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:border-bookBlue cursor-pointer text-slate-700 dark:text-white"
                        >
                           <option value="newest">Terbaru</option>
                           <option value="low-high">Harga Terendah</option>
                           <option value="high-low">Harga Tertinggi</option>
                        </select>
                        <FiChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                     </div>
                  </div>
               </div>

               {/* Grid Buku */}
               {filteredBooks.length > 0 ? (
                  <motion.div layout className="grid grid-cols-2 md:grid-cols-3 gap-6">
                     {filteredBooks.map((b) => (
                        <motion.div
                           layout
                           key={b.id}
                           initial={{ opacity: 0, scale: 0.9 }}
                           animate={{ opacity: 1, scale: 1 }}
                           transition={{ duration: 0.3 }}
                        >
                           <BookCard book={b} onQuickView={(data) => setSelectedBook(data)} />
                        </motion.div>
                     ))}
                  </motion.div>
               ) : (
                  <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-800 rounded-xl border border-dashed border-slate-300 dark:border-slate-700">
                     <div className="p-4 bg-slate-100 dark:bg-slate-700 rounded-full mb-4">
                        <FiSearch className="w-8 h-8 text-slate-400" />
                     </div>
                     <h3 className="text-lg font-bold text-slate-900 dark:text-white">Buku tidak ditemukan</h3>
                     <p className="text-slate-500 text-sm mt-1 mb-6">Coba kurangi filter atau gunakan kata kunci lain.</p>
                     <button onClick={handleReset} className="flex items-center gap-2 px-5 py-2 bg-bookBlue text-white rounded-lg hover:bg-blue-900 transition-colors text-sm font-bold">
                        <FiX /> Reset Filter
                     </button>
                  </div>
               )}
            </div>
         </div>
      </section>
   );
}
