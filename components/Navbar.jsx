"use client";

import Link from "next/link";
import DarkToggle from "./DarkToggle";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
// Tambahkan FiUser, FiSettings, FiList (Ikon baru)
import { FiSearch, FiShoppingCart, FiHeart, FiChevronDown, FiLogOut, FiUser, FiSettings, FiList } from "react-icons/fi";
import useStore from "../store/store";

const categories = ["Business", "Finance", "Startup", "Design", "Poetry"];

export default function Navbar() {
   const [q, setQ] = useState("");
   const router = useRouter();

   const setQuery = useStore((s) => s.setQuery);
   const setSelectedCategory = useStore((s) => s.setSelectedCategory);
   const cartCount = useStore((s) => s.cart.length);
   const wishlistCount = useStore((s) => s.wishlist.length);
   
   // State Login Global
   const isLoggedIn = useStore((s) => s.isLoggedIn);
   const setLoggedIn = useStore((s) => s.setLoggedIn);

   useEffect(() => {
      const hasToken = document.cookie.includes("token=");
      setLoggedIn(hasToken);
   }, [setLoggedIn]);

   const handleLogout = () => {
      document.cookie = "token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; max-age=0"; 
      setLoggedIn(false); 
      router.push("/"); 
      router.refresh(); 
   };

   function onSearch(e) {
      e.preventDefault();
      setQuery(q);
      router.push("/katalog");
   }

   const handleCategoryClick = (cat) => {
      setQuery("");
      setSelectedCategory(cat);
      router.push("/katalog");
   };

   return (
      <header className="sticky top-0 z-50 w-full backdrop-blur-md bg-white/90 dark:bg-slate-900/90 border-b border-gray-200 dark:border-slate-800 transition-colors duration-300">
         <div className="container flex items-center justify-between py-3">
            
            <Link href="/" className="flex items-center gap-3 group">
               <img src="/logo-hitam.png" alt="Paperbloom Logo" className="h-100 w-auto md:h-20 object-contain transition-transform group-hover:scale-105 dark:hidden" />
               <img src="/logo-putih.png" alt="Paperbloom Logo Dark" className="h-100 w-auto md:h-20 object-contain transition-transform group-hover:scale-105 hidden dark:block" />
            </Link>

            <form onSubmit={onSearch} className="hidden md:block flex-1 mx-8 max-w-lg">
               <div className="relative group">
                  <input
                     value={q}
                     onChange={(e) => setQ(e.target.value)}
                     placeholder="Cari buku inspirasimu..."
                     className="w-full rounded-full border border-gray-300 bg-gray-100 px-4 py-2 pl-10 text-sm outline-none transition-all 
                                focus:border-bookBlue focus:bg-white focus:ring-2 focus:ring-blue-200
                                dark:border-slate-700 dark:bg-slate-800 dark:text-white dark:focus:border-bookBlue dark:focus:bg-slate-800 dark:focus:ring-blue-900"
                  />
                  <button type="submit" className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 group-hover:text-bookBlue transition-colors">
                     <FiSearch />
                  </button>
               </div>
            </form>

            <nav className="flex items-center gap-4 md:gap-6 text-gray-700 dark:text-gray-300">
               
               <div className="relative group hidden md:block">
                  <button className="flex items-center gap-1 text-sm font-medium hover:text-bookBlue dark:hover:text-blue-400 transition-colors py-4">
                     Kategori <FiChevronDown />
                  </button>
                  <div className="absolute top-full left-0 w-48 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-100 dark:border-slate-700 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 transform group-hover:translate-y-0 translate-y-2 overflow-hidden">
                     <div className="p-2 flex flex-col">
                        {categories.map((cat) => (
                           <button key={cat} onClick={() => handleCategoryClick(cat)} className="text-left px-4 py-2 text-sm rounded-lg hover:bg-blue-50 dark:hover:bg-slate-700 hover:text-bookBlue dark:hover:text-blue-400 transition-colors">
                              {cat}
                           </button>
                        ))}
                     </div>
                  </div>
               </div>

               <Link href="/katalog" className="hidden md:block text-sm font-medium hover:text-bookBlue dark:hover:text-blue-400 transition-colors">Katalog</Link>
               
               <Link href="/promo" className="hidden md:block text-sm font-medium hover:text-bookBlue dark:hover:text-blue-400 transition-colors relative group">
                  Promo
                  <span className="absolute -top-1 -right-2 h-2 w-2 bg-red-500 rounded-full animate-pulse"></span>
               </Link>

               <Link href="/#blog-section" className="hidden md:block text-sm font-medium hover:text-bookBlue dark:hover:text-blue-400 transition-colors">Blog</Link>

               <div className="flex items-center gap-2 pl-2 sm:border-l border-gray-300 dark:border-slate-700 sm:pl-5">
                  <Link href="/wishlist" className="relative p-2 hover:bg-gray-100 dark:hover:bg-slate-800 rounded-full transition-all">
                     <FiHeart className="w-5 h-5" />
                     {wishlistCount > 0 && <span className="absolute top-0 right-0 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] text-white animate-bounce">{wishlistCount}</span>}
                  </Link>

                  <Link href="/cart" className="relative p-2 hover:bg-gray-100 dark:hover:bg-slate-800 rounded-full transition-all">
                     <FiShoppingCart className="w-5 h-5" />
                     {cartCount > 0 && <span className="absolute top-0 right-0 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] text-white animate-bounce">{cartCount}</span>}
                  </Link>
                  
                  <DarkToggle />

                  {/* --- BAGIAN USER PROFILE (GANTIKAN TOMBOL LOGOUT LAMA) --- */}
                  {isLoggedIn ? (
                     <div className="relative group ml-2">
                        {/* 1. Ikon User (Trigger) */}
                        <button className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors">
                           <div className="w-8 h-8 bg-bookBlue text-white rounded-full flex items-center justify-center font-bold text-sm shadow-md">
                              <FiUser />
                           </div>
                           <FiChevronDown className="w-4 h-4 text-gray-500 group-hover:rotate-180 transition-transform" />
                        </button>

                        {/* 2. Dropdown Menu Profil */}
                        <div className="absolute top-full right-0 w-56 bg-white dark:bg-slate-800 rounded-xl shadow-2xl border border-gray-100 dark:border-slate-700 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 transform group-hover:translate-y-0 translate-y-2 overflow-hidden z-50">
                           
                           {/* Header Dropdown */}
                           <div className="px-4 py-3 border-b border-gray-100 dark:border-slate-700 bg-gray-50 dark:bg-slate-900/50">
                              <p className="text-xs text-gray-500 dark:text-gray-400">Halo, Selamat Datang!</p>
                              <p className="text-sm font-bold text-slate-900 dark:text-white truncate">Member PaperBloom</p>
                           </div>

                           {/* Menu Items */}
                           <div className="p-2 flex flex-col gap-1">
                              <Link href="/profile" className="flex items-center gap-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                 <FiUser className="text-bookBlue" /> Profil Saya
                              </Link>
                              <Link href="/orders" className="flex items-center gap-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                 <FiList className="text-bookBlue" /> Riwayat Pesanan
                              </Link>
                              <Link href="/settings" className="flex items-center gap-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                 <FiSettings className="text-bookBlue" /> Pengaturan
                              </Link>
                           </div>

                           {/* Tombol Logout di dalam Dropdown */}
                           <div className="p-2 border-t border-gray-100 dark:border-slate-700">
                              <button 
                                 onClick={handleLogout}
                                 className="w-full flex items-center gap-3 px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors font-medium"
                              >
                                 <FiLogOut /> Logout
                              </button>
                           </div>
                        </div>
                     </div>
                  ) : (
                     <Link href="/auth/login" className="ml-2 px-5 py-2 bg-bookBlue hover:bg-blue-900 text-white rounded-lg text-xs font-bold shadow-md hover:shadow-lg transition-all">
                        Masuk
                     </Link>
                  )}
                  {/* ------------------------------------------------------- */}

               </div>
            </nav>
         </div>
      </header>
   );
}
