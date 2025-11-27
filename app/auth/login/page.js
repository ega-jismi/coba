'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { FiMail, FiLock, FiArrowRight, FiChrome, FiGithub, FiUser, FiCheckCircle } from 'react-icons/fi';
import useStore from '../../../store/store'; 

export default function AuthPage() {
  const router = useRouter();
  const setLoggedIn = useStore((s) => s.setLoggedIn);

  // --- STATE MODE (LOGIN / REGISTER) ---
  const [isLoginMode, setIsLoginMode] = useState(true); // Default: Mode Login
  const [isLoading, setIsLoading] = useState(false);

  // State Form
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPass, setConfirmPass] = useState('');

  // --- LOGIKA SUBMIT (Satu fungsi untuk keduanya) ---
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validasi Khusus Register
    if (!isLoginMode) {
        if (password !== confirmPass) {
            alert("Password konfirmasi tidak cocok!");
            return;
        }
        if (!name) {
            alert("Nama harus diisi!");
            return;
        }
    }

    setIsLoading(true);
    
    // Simulasi Proses Server
    setTimeout(() => {
      // 1. Simpan Token
      document.cookie = "token=token-palsu-bebas; path=/; max-age=86400"; 
      
      // 2. Update Global Store (Agar Navbar berubah)
      setLoggedIn(true); 
      window.dispatchEvent(new Event("auth-change"));

      // 3. Pindah ke Home
      router.push('/'); 
      setIsLoading(false);
    }, 1500);
  };

  // Fungsi Ganti Mode
  const toggleMode = () => {
      setIsLoginMode(!isLoginMode);
      // Reset form saat ganti mode agar bersih
      setName('');
      setEmail('');
      setPassword('');
      setConfirmPass('');
  };

  return (
    <div className="min-h-screen flex bg-white dark:bg-slate-900">
      
      {/* BAGIAN KIRI: GAMBAR (Quote berubah sesuai mode) */}
      <div className="hidden md:flex w-1/2 bg-slate-800 relative overflow-hidden">
        <div 
            className="absolute inset-0 z-0"
            style={{
                backgroundImage: "url('https://images.unsplash.com/photo-1481627834876-b7833e8f5570?q=80&w=2228&auto=format&fit=crop')",
                backgroundSize: 'cover',
                backgroundPosition: 'center',
                filter: 'brightness(0.6)'
            }}
        />
        <div className="relative z-10 flex flex-col justify-between h-full p-12 text-white">
            <div className="flex items-center gap-2">
                <img src="/logo-putih.png" alt="Logo" className="h-8 w-auto opacity-80" />
            </div>
            <div className="mb-10">
                <h2 className="text-4xl font-serif font-bold mb-4 leading-tight">
                    {isLoginMode 
                        ? '"Buku adalah cermin jiwa.\nTemukan dirimu di setiap halamannya."' 
                        : '"Bergabunglah dengan komunitas\npembaca terbesar di Indonesia."'
                    }
                </h2>
                <p className="text-slate-300 text-lg">— Paper Bloom Community</p>
            </div>
        </div>
      </div>

      {/* BAGIAN KANAN: FORM DINAMIS */}
      <div className="w-full md:w-1/2 flex items-center justify-center p-8 md:p-16 relative overflow-y-auto">
        <Link href="/" className="absolute top-6 left-6 text-sm text-slate-500 hover:text-bookBlue flex items-center gap-2 transition-colors">
            ← Kembali ke Beranda
        </Link>

        <div className="max-w-md w-full py-10">
            <div className="text-center mb-8">
                <img src="/logo-hitam.png" alt="Paper Bloom" className="h-100 mx-auto mb-20 dark:hidden" />
                <img src="/logo-putih.png" alt="Paper Bloom" className="h-100 mx-auto mb-20 hidden dark:block" />
                
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
                    {isLoginMode ? 'Selamat Datang Kembali' : 'Buat Akun Baru'}
                </h1>
                <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
                    {isLoginMode ? 'Masuk untuk melanjutkan belanja.' : 'Isi data diri untuk mulai berbelanja.'}
                </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
                
                {/* Input Nama (Hanya muncul saat Register) */}
                <AnimatePresence>
                    {!isLoginMode && (
                        <motion.div 
                            initial={{ opacity: 0, height: 0 }} 
                            animate={{ opacity: 1, height: 'auto' }} 
                            exit={{ opacity: 0, height: 0 }}
                            className="space-y-1 overflow-hidden"
                        >
                            <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Nama Lengkap</label>
                            <div className="relative">
                                <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><FiUser /></div>
                                <input type="text" required={!isLoginMode} value={name} onChange={(e) => setName(e.target.value)} className="w-full pl-10 pr-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-bookBlue outline-none transition-all" placeholder="Jhon Doe"/>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Input Email */}
                <div className="space-y-1">
                    <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Email Address</label>
                    <div className="relative">
                        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><FiMail /></div>
                        <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full pl-10 pr-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-bookBlue outline-none transition-all" placeholder="nama@email.com"/>
                    </div>
                </div>

                {/* Input Password */}
                <div className="space-y-1">
                    <div className="flex justify-between">
                        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Password</label>
                        {isLoginMode && <a href="#" className="text-xs text-bookBlue hover:underline">Lupa Password?</a>}
                    </div>
                    <div className="relative">
                        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><FiLock /></div>
                        <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className="w-full pl-10 pr-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-bookBlue outline-none transition-all" placeholder="••••••••"/>
                    </div>
                </div>

                {/* Input Konfirmasi Password (Hanya Register) */}
                <AnimatePresence>
                    {!isLoginMode && (
                        <motion.div 
                            initial={{ opacity: 0, height: 0 }} 
                            animate={{ opacity: 1, height: 'auto' }} 
                            exit={{ opacity: 0, height: 0 }}
                            className="space-y-1 overflow-hidden"
                        >
                            <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Ulangi Password</label>
                            <div className="relative">
                                <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><FiCheckCircle /></div>
                                <input type="password" required={!isLoginMode} value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)} className="w-full pl-10 pr-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-bookBlue outline-none transition-all" placeholder="••••••••"/>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Tombol Submit */}
                <motion.button 
                    whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
                    disabled={isLoading}
                    className="w-full py-3.5 bg-bookBlue hover:bg-blue-900 text-white font-bold rounded-xl shadow-lg transition-all flex items-center justify-center gap-2 mt-6"
                >
                    {isLoading ? 'Memproses...' : (isLoginMode ? <>Masuk Sekarang <FiArrowRight/></> : <>Daftar Akun <FiArrowRight/></>)}
                </motion.button>
            </form>

            <div className="relative my-8">
                <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-200 dark:border-slate-700"></div></div>
                <div className="relative flex justify-center text-xs uppercase"><span className="bg-white dark:bg-slate-900 px-2 text-slate-400">Atau masuk dengan</span></div>
            </div>

            <div className="grid grid-cols-2 gap-4">
                <button className="flex items-center justify-center gap-2 py-2.5 border border-slate-200 dark:border-slate-700 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors text-sm font-medium text-slate-700 dark:text-slate-300"><FiChrome className="text-red-500" /> Google</button>
                <button className="flex items-center justify-center gap-2 py-2.5 border border-slate-200 dark:border-slate-700 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors text-sm font-medium text-slate-700 dark:text-slate-300"><FiGithub /> GitHub</button>
            </div>

            {/* TOMBOL TOGGLE MODE (Ganti antara Login/Register) */}
            <p className="text-center text-sm text-slate-500 mt-8">
                {isLoginMode ? 'Belum punya akun? ' : 'Sudah punya akun? '}
                <button 
                    onClick={toggleMode}
                    className="font-bold text-bookBlue hover:underline focus:outline-none"
                >
                    {isLoginMode ? 'Daftar Gratis' : 'Masuk Sekarang'}
                </button>
            </p>
        </div>
      </div>
    </div>
  );
}
