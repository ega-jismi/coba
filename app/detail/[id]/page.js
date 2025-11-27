"use client";

import { useState } from "react";
import Link from "next/link";
import { books, reviews } from "../../../lib/mock"; // Path mundur 3x
import BookCard from "../../../components/BookCard"; // Path mundur 3x
import { motion } from "framer-motion";
import { FiShoppingCart, FiHeart, FiCheckCircle, FiTruck, FiShield, FiMinus, FiPlus, FiStar } from "react-icons/fi";
import useStore from "../../../store/store"; // Path mundur 3x

export default function Detail({ params }) {
   const book = books.find((b) => b.id === params.id);
   const addToCart = useStore((s) => s.addToCart);
   
   // State untuk Ulasan
   const initialReviews = (book && reviews && reviews[book.id]) ? reviews[book.id] : [];
   const [reviewList, setReviewList] = useState(initialReviews);
   
   // State Form & Quantity
   const [name, setName] = useState("");
   const [comment, setComment] = useState("");
   const [rating, setRating] = useState(5);
   const [qty, setQty] = useState(1); 

   if (!book) return <div className="p-10 text-center text-gray-500">Buku tidak ditemukan</div>;

   const related = books.filter((b) => b.id !== book.id).slice(0, 4); 

   // Logika Harga
   const originalPrice = Number(book.price) || 0;
   const discount = book.discount || 0;
   const hasDiscount = discount > 0;
   const finalPrice = hasDiscount ? originalPrice - (originalPrice * discount / 100) : originalPrice;

   const handleSubmit = (e) => {
      e.preventDefault();
      if (!name || !comment) return;
      const newReview = { id: Date.now(), user: name, rating: Number(rating), text: comment };
      setReviewList([newReview, ...reviewList]);
      setName(""); setComment(""); setRating(5);
   };

   const handleAdd = () => {
      for(let i=0; i<qty; i++) {
         addToCart({...book, price: finalPrice});
      }
   };

   return (
      <section className="max-w-6xl mx-auto pb-10 px-4">
         
         {/* BREADCRUMBS */}
         <div className="text-sm text-slate-500 dark:text-slate-400 mb-6 flex items-center gap-2">
            <Link href="/" className="hover:text-bookBlue transition-colors">Home</Link>
            <span>/</span>
            <Link href="/katalog" className="hover:text-bookBlue transition-colors">Katalog</Link>
            <span>/</span>
            <span className="text-slate-900 dark:text-white font-medium truncate">{book.title}</span>
         </div>

         <div className="grid md:grid-cols-12 gap-8 lg:gap-12">
            
            {/* KOLOM KIRI: GAMBAR */}
            <motion.div 
               initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} 
               className="md:col-span-4 lg:col-span-4"
            >
               <div className="p-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-lg sticky top-24">
                  <img src={book.cover} alt={book.title} className="w-full h-auto rounded-lg" />
               </div>
            </motion.div>

            {/* KOLOM KANAN: DETAIL INFO */}
            <motion.div 
               initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} 
               className="md:col-span-8 lg:col-span-8"
            >
               {/* Judul & Penulis */}
               <div className="mb-1">
                  <span className="bg-blue-100 dark:bg-blue-900/30 text-bookBlue dark:text-blue-300 text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wide">
                     {book.tags?.[0] || "Buku"}
                  </span>
               </div>
               <h1 className="text-3xl md:text-4xl font-serif font-bold text-slate-900 dark:text-white mb-2 leading-tight">
                  {book.title}
               </h1>
               <div className="flex items-center gap-4 text-sm mb-6">
                  <span className="text-slate-600 dark:text-slate-400">Oleh: <span className="text-bookBlue font-semibold">{book.author}</span></span>
                  <div className="flex items-center text-yellow-400">
                     <FiStar className="fill-current" /> 4.8 <span className="text-slate-400 ml-1">(20 Ulasan)</span>
                  </div>
               </div>

               {/* Harga */}
               <div className="p-6 bg-slate-50 dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 mb-8">
                  <div className="flex items-end gap-3 mb-4">
                     <div className="text-4xl font-bold text-bookOrange">
                        Rp {finalPrice.toLocaleString("id-ID")}
                     </div>
                     {hasDiscount && (
                        <div className="mb-1">
                           <span className="text-sm text-slate-400 line-through mr-2">Rp {originalPrice.toLocaleString("id-ID")}</span>
                           <span className="text-xs font-bold text-red-500 bg-red-100 dark:bg-red-900/30 px-2 py-0.5 rounded">Hemat {discount}%</span>
                        </div>
                     )}
                  </div>

                  {/* Tombol Aksi */}
                  <div className="flex flex-col sm:flex-row gap-4">
                     {/* Quantity Selector */}
                     <div className="flex items-center border border-slate-300 dark:border-slate-600 rounded-xl bg-white dark:bg-slate-900 h-12 w-fit">
                        <button onClick={() => setQty(Math.max(1, qty - 1))} className="px-4 text-slate-500 hover:text-bookBlue"><FiMinus/></button>
                        <span className="w-8 text-center font-bold text-slate-900 dark:text-white">{qty}</span>
                        <button onClick={() => setQty(qty + 1)} className="px-4 text-slate-500 hover:text-bookBlue"><FiPlus/></button>
                     </div>

                     {/* Add to Cart */}
                     <button 
                        onClick={handleAdd}
                        className="flex-1 h-12 bg-bookBlue hover:bg-blue-900 text-white font-bold rounded-xl shadow-lg hover:shadow-blue-500/20 transition-all flex items-center justify-center gap-2"
                     >
                        <FiShoppingCart className="w-5 h-5" /> Tambah Keranjang
                     </button>

                     {/* Wishlist */}
                     <button className="h-12 w-12 border border-slate-300 dark:border-slate-600 rounded-xl flex items-center justify-center text-slate-500 hover:text-red-500 hover:border-red-500 transition-colors">
                        <FiHeart className="w-5 h-5" />
                     </button>
                  </div>

                  {/* Jaminan Layanan */}
                  <div className="grid grid-cols-3 gap-2 mt-6 pt-6 border-t border-slate-200 dark:border-slate-700 text-xs md:text-sm text-slate-600 dark:text-slate-400">
                     <div className="flex flex-col items-center gap-1 text-center">
                        <FiCheckCircle className="text-green-500 w-5 h-5" /> <span>100% Original</span>
                     </div>
                     <div className="flex flex-col items-center gap-1 text-center">
                        <FiTruck className="text-bookBlue w-5 h-5" /> <span>Kirim Cepat</span>
                     </div>
                     <div className="flex flex-col items-center gap-1 text-center">
                        <FiShield className="text-purple-500 w-5 h-5" /> <span>Transaksi Aman</span>
                     </div>
                  </div>
               </div>

               {/* DETAIL SPESIFIKASI (DINAMIS) */}
               <div className="mb-8">
                  <h3 className="text-lg font-serif font-bold text-slate-900 dark:text-white mb-4 border-b border-slate-200 dark:border-slate-700 pb-2">
                     Deskripsi & Spesifikasi
                  </h3>
                  <p className="text-slate-600 dark:text-slate-300 leading-relaxed mb-6">
                     {book.description}
                  </p>

                  {/* --- BAGIAN INI YANG SUDAH DIPERBAIKI --- */}
                  <div className="grid grid-cols-2 gap-4 text-sm">
                     <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                        <span className="block text-slate-400 text-xs uppercase">ISBN</span>
                        <span className="font-semibold text-slate-900 dark:text-white">{book.isbn || "-"}</span>
                     </div>
                     <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                        <span className="block text-slate-400 text-xs uppercase">Penerbit</span>
                        <span className="font-semibold text-slate-900 dark:text-white">{book.publisher || "-"}</span>
                     </div>
                     <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                        <span className="block text-slate-400 text-xs uppercase">Halaman</span>
                        <span className="font-semibold text-slate-900 dark:text-white">{book.pages || "-"} Halaman</span>
                     </div>
                     <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
                        <span className="block text-slate-400 text-xs uppercase">Berat</span>
                        <span className="font-semibold text-slate-900 dark:text-white">{book.weight || "-"} kg</span>
                     </div>
                  </div>
                  {/* ---------------------------------------- */}
               </div>

            </motion.div>
         </div>

         <div className="border-t border-slate-200 dark:border-slate-800 my-12" />

         {/* AREA ULASAN */}
         <div className="grid md:grid-cols-2 gap-10 mb-16">
            <div>
               <h3 className="text-2xl font-serif font-bold mb-6 text-slate-900 dark:text-white">Ulasan Pembaca</h3>
               <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                  {reviewList.length > 0 ? (
                     reviewList.map((r) => (
                        <div key={r.id} className="p-5 border border-slate-200 dark:border-slate-700 rounded-2xl bg-slate-50 dark:bg-slate-800/50">
                           <div className="flex justify-between mb-2">
                              <div className="font-bold text-slate-900 dark:text-white">{r.user}</div>
                              <div className="flex text-yellow-400 text-xs">{"★".repeat(r.rating)}</div>
                           </div>
                           <p className="text-slate-600 dark:text-slate-300 text-sm">"{r.text}"</p>
                        </div>
                     ))
                  ) : (
                     <p className="text-slate-500 italic">Belum ada ulasan.</p>
                  )}
               </div>
            </div>

            <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 h-fit">
               <h3 className="text-lg font-bold mb-4 text-slate-900 dark:text-white">Tulis Ulasan</h3>
               <form onSubmit={handleSubmit} className="space-y-4">
                  <input type="text" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Nama Anda"
                     className="w-full px-4 py-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-600 outline-none focus:border-bookBlue transition-all"
                  />
                  <div className="flex gap-2">
                     {[1,2,3,4,5].map(num => (
                        <button key={num} type="button" onClick={() => setRating(num)} 
                           className={`w-8 h-8 rounded-lg font-bold border ${rating === num ? 'bg-yellow-400 border-yellow-400 text-white' : 'border-slate-300 text-slate-400'}`}>
                           {num}
                        </button>
                     ))}
                  </div>
                  <textarea required value={comment} onChange={(e) => setComment(e.target.value)} rows="3" placeholder="Pendapat Anda..."
                     className="w-full px-4 py-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-600 outline-none focus:border-bookBlue transition-all"
                  ></textarea>
                  <button type="submit" className="w-full py-3 bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-bold rounded-xl hover:opacity-90 transition-all">
                     Kirim Ulasan
                  </button>
               </form>
            </div>
         </div>

         {/* REKOMENDASI LAIN */}
         <div>
            <h3 className="text-2xl font-serif font-bold mb-6 text-slate-900 dark:text-white border-l-4 border-bookBlue pl-4">
               Mungkin Anda Suka
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6">
               {related.map((b) => (
                  <BookCard key={b.id} book={b} />
               ))}
            </div>
         </div>

      </section>
   );
}
