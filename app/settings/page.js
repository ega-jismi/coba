"use client";

import { useState } from "react";
import { FiLock, FiBell, FiGlobe, FiToggleRight } from "react-icons/fi";

export default function SettingsPage() {
  return (
    <section className="max-w-3xl mx-auto min-h-screen pb-10">
      <h1 className="text-3xl font-serif font-bold text-slate-900 dark:text-white mb-8 border-b pb-4 border-slate-200 dark:border-slate-700">
        Pengaturan Akun
      </h1>

      <div className="space-y-6">
        
        {/* Keamanan */}
        <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <FiLock /> Keamanan
            </h3>
            <div className="space-y-4">
                <div>
                    <label className="block text-xs font-bold text-slate-500 mb-1">Password Lama</label>
                    <input type="password" placeholder="••••••••" className="w-full px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-600 bg-transparent" />
                </div>
                <div>
                    <label className="block text-xs font-bold text-slate-500 mb-1">Password Baru</label>
                    <input type="password" placeholder="••••••••" className="w-full px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-600 bg-transparent" />
                </div>
                <button className="px-4 py-2 bg-slate-900 dark:bg-white text-white dark:text-slate-900 text-sm font-bold rounded-lg">Update Password</button>
            </div>
        </div>

        {/* Notifikasi */}
        <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <FiBell /> Notifikasi
            </h3>
            <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700">
                <span className="text-sm text-slate-700 dark:text-slate-300">Terima email promo terbaru</span>
                <div className="w-10 h-6 bg-bookBlue rounded-full relative cursor-pointer"><div className="absolute right-1 top-1 w-4 h-4 bg-white rounded-full"></div></div>
            </div>
            <div className="flex justify-between items-center py-2">
                <span className="text-sm text-slate-700 dark:text-slate-300">Notifikasi status pesanan</span>
                <div className="w-10 h-6 bg-bookBlue rounded-full relative cursor-pointer"><div className="absolute right-1 top-1 w-4 h-4 bg-white rounded-full"></div></div>
            </div>
        </div>

        {/* Danger Zone */}
        <div className="p-6 rounded-2xl border border-red-200 bg-red-50 dark:bg-red-900/20">
            <h3 className="text-lg font-bold text-red-600 mb-2">Zona Bahaya</h3>
            <p className="text-sm text-red-500 mb-4">Menghapus akun akan menghilangkan semua riwayat pesanan secara permanen.</p>
            <button className="px-4 py-2 border border-red-500 text-red-600 text-sm font-bold rounded-lg hover:bg-red-100 transition-colors">
                Hapus Akun Saya
            </button>
        </div>

      </div>
    </section>
  );
}
