"use client";

import { useState } from "react";
import { FiUser, FiMapPin, FiPhone, FiMail, FiSave } from "react-icons/fi";

export default function ProfilePage() {
  const [isLoading, setIsLoading] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    setIsLoading(true);
    setTimeout(() => setIsLoading(false), 1500);
  };

  return (
    <section className="max-w-4xl mx-auto min-h-screen pb-10">
      <h1 className="text-3xl font-serif font-bold text-slate-900 dark:text-white mb-8 border-b pb-4 border-slate-200 dark:border-slate-700">
        Profil Saya
      </h1>

      <div className="grid md:grid-cols-3 gap-8">
        {/* KIRI: FOTO PROFIL */}
        <div className="md:col-span-1">
          <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 text-center shadow-sm">
            <div className="w-32 h-32 mx-auto bg-bookBlue rounded-full flex items-center justify-center text-4xl text-white font-bold mb-4">
              MP
            </div>
            <h2 className="font-bold text-lg text-slate-900 dark:text-white">Member PaperBloom</h2>
            <p className="text-sm text-slate-500 mb-4">Bergabung sejak 2025</p>
            <button className="text-sm text-bookBlue font-bold hover:underline">Ubah Foto</button>
          </div>
        </div>

        {/* KANAN: FORM DATA DIRI */}
        <div className="md:col-span-2">
          <form onSubmit={handleSave} className="bg-white dark:bg-slate-800 p-8 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm space-y-6">
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Nama Lengkap</label>
                    <div className="flex items-center border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2.5">
                        <FiUser className="text-slate-400 mr-3" />
                        <input type="text" defaultValue="Member PaperBloom" className="w-full bg-transparent outline-none text-slate-900 dark:text-white text-sm"/>
                    </div>
                </div>
                <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Nomor Telepon</label>
                    <div className="flex items-center border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2.5">
                        <FiPhone className="text-slate-400 mr-3" />
                        <input type="text" defaultValue="0812-3456-7890" className="w-full bg-transparent outline-none text-slate-900 dark:text-white text-sm"/>
                    </div>
                </div>
            </div>

            <div>
                <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Email</label>
                <div className="flex items-center border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2.5 bg-slate-50 dark:bg-slate-900">
                    <FiMail className="text-slate-400 mr-3" />
                    <input type="text" defaultValue="member@paperbloom.com" disabled className="w-full bg-transparent outline-none text-slate-500 cursor-not-allowed text-sm"/>
                </div>
                <p className="text-[10px] text-slate-400 mt-1">*Email tidak dapat diubah</p>
            </div>

            <div>
                <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Alamat Pengiriman</label>
                <div className="flex items-start border border-slate-300 dark:border-slate-600 rounded-lg px-3 py-2.5">
                    <FiMapPin className="text-slate-400 mr-3 mt-1" />
                    <textarea rows="3" defaultValue="Jl. Buku Baru No. 123, Jakarta Selatan, DKI Jakarta" className="w-full bg-transparent outline-none text-slate-900 dark:text-white text-sm resize-none"></textarea>
                </div>
            </div>

            <div className="pt-4 border-t border-slate-100 dark:border-slate-700 text-right">
                <button className="px-6 py-3 bg-bookBlue hover:bg-blue-900 text-white font-bold rounded-xl shadow-lg transition-all flex items-center gap-2 ml-auto">
                    {isLoading ? "Menyimpan..." : <><FiSave /> Simpan Perubahan</>}
                </button>
            </div>

          </form>
        </div>
      </div>
    </section>
  );
}
