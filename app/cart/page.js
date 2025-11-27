"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import useStore from "../../store/store"; // Pastikan path ini benar
import { motion, AnimatePresence } from "framer-motion";

const paymentMethods = [
  { id: "qris", name: "QRIS (Scan Barcode)", icon: "📱" },
  { id: "bca", name: "Bank BCA", icon: "🏦" },
  { id: "mandiri", name: "Bank Mandiri", icon: "🏦" },
  { id: "gopay", name: "GoPay", icon: "🟢" },
  { id: "ovo", name: "OVO", icon: "🟣" },
  { id: "cod", name: "Bayar di Tempat (COD)", icon: "🚚" },
];

export default function Cart() {
  const router = useRouter();
  
  // 1. AMBIL FUNGSI clearCart DARI STORE
  const cart = useStore((s) => s.cart);
  const remove = useStore((s) => s.removeFromCart);
  const clearCart = useStore((s) => s.clearCart); 

  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [selectedPayment, setSelectedPayment] = useState(paymentMethods[0].id);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const total = cart.reduce((sum, i) => sum + i.price * i.qty, 0);

  const handleCheckout = () => {
    const hasToken = document.cookie.includes("token=");
    if (!hasToken) {
      setShowLoginModal(true);
    } else {
      setShowPaymentModal(true);
    }
  };

  // --- FUNGSI PEMBAYARAN DIUPDATE DI SINI ---
  const handlePay = () => {
    setIsProcessing(true);

    setTimeout(() => {
      setIsProcessing(false);
      setIsSuccess(true);
      
      // 2. KOSONGKAN KERANJANG DI SINI
      // Buku akan hilang di background, tapi modal sukses tetap muncul
      clearCart(); 
      
    }, 2000);
  };

  const closePaymentModal = () => {
    setShowPaymentModal(false);
    setIsSuccess(false);
    setIsProcessing(false);
    // Opsional: Redirect ke halaman utama setelah tutup modal sukses
    // router.push('/'); 
  };

  const confirmRedirectLogin = () => {
    setShowLoginModal(false);
    router.push("/auth/login");
  };

  // Variabel animasi
  const listVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.1 } },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0 },
  };

  return (
    <section className="relative min-h-[50vh]">
      <h1 className="text-2xl font-bold mb-4 text-white">Keranjang</h1>

      {/* --- MODAL LOGIN --- */}
      <AnimatePresence>
        {showLoginModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowLoginModal(false)}
              className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            />
            <motion.div
              initial={{ scale: 0.5, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.5, opacity: 0 }}
              className="relative z-10 w-full max-w-sm bg-gray-800 border border-gray-700 rounded-2xl p-6 shadow-2xl text-center"
            >
              <div className="mb-4 text-4xl">🔒</div>
              <h3 className="text-xl font-bold text-white mb-2">Akses Dibatasi</h3>
              <p className="text-gray-300 mb-6">Silakan login untuk melanjutkan pembayaran.</p>
              <div className="flex gap-3 justify-center">
                <button onClick={() => setShowLoginModal(false)} className="px-4 py-2 rounded-lg text-gray-300 hover:bg-gray-700">Batal</button>
                <button onClick={confirmRedirectLogin} className="px-4 py-2 rounded-lg bg-blue-600 text-white font-semibold hover:bg-blue-700">Login Sekarang</button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* --- MODAL PEMBAYARAN --- */}
      <AnimatePresence>
        {showPaymentModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={closePaymentModal} // Klik background tutup modal
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />

            <motion.div
              initial={{ y: 50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 50, opacity: 0 }}
              className="relative z-10 w-full max-w-md bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl overflow-hidden"
            >
              <div className="p-4 border-b border-gray-800 flex justify-between items-center">
                <h3 className="text-lg font-bold text-white">Pilih Pembayaran</h3>
                <button onClick={closePaymentModal} className="text-gray-400 hover:text-white">✕</button>
              </div>

              <div className="p-6 max-h-[60vh] overflow-y-auto">
                {!isSuccess ? (
                  <div className="space-y-3">
                    {paymentMethods.map((method) => (
                      <div
                        key={method.id}
                        onClick={() => setSelectedPayment(method.id)}
                        className={`flex items-center justify-between p-4 rounded-xl border cursor-pointer transition-all ${
                          selectedPayment === method.id
                            ? "border-green-500 bg-green-900/20"
                            : "border-gray-700 bg-gray-800 hover:border-gray-500"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{method.icon}</span>
                          <span className="text-white font-medium">{method.name}</span>
                        </div>
                        {selectedPayment === method.id && (
                          <div className="w-4 h-4 rounded-full bg-green-500 shadow-[0_0_10px_#22c55e]"></div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  // TAMPILAN SUKSES
                  <div className="flex flex-col items-center justify-center py-8">
                    <motion.div
                      initial={{ scale: 0 }} animate={{ scale: 1 }}
                      className="w-20 h-20 bg-green-500 rounded-full flex items-center justify-center text-4xl mb-4 shadow-lg shadow-green-500/50"
                    >
                      🎉
                    </motion.div>
                    <h2 className="text-2xl font-bold text-white mb-2">Pembayaran Berhasil!</h2>
                    <p className="text-gray-400 text-center">Terima kasih telah berbelanja.</p>
                  </div>
                )}
              </div>

              {/* FOOTER MODAL */}
              {!isSuccess && (
                <div className="p-4 border-t border-gray-800 bg-gray-900">
                  <div className="flex justify-between items-center mb-4 text-gray-300">
                    <span>Total Tagihan:</span>
                    <span className="text-xl font-bold text-white">Rp {total.toLocaleString("id-ID")}</span>
                  </div>
                  <button
                    onClick={handlePay}
                    disabled={isProcessing}
                    className="w-full py-3 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold rounded-xl shadow-lg transition-transform active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2"
                  >
                    {isProcessing ? (
                      <>
                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        Memproses...
                      </>
                    ) : (
                      "Bayar Sekarang"
                    )}
                  </button>
                </div>
              )}
              
              {isSuccess && (
                <div className="p-4 border-t border-gray-800 bg-gray-900">
                   <button
                    onClick={closePaymentModal}
                    className="w-full py-3 bg-gray-700 hover:bg-gray-600 text-white font-bold rounded-xl"
                  >
                    Tutup
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* --- KONTEN KERANJANG --- */}
      {cart.length === 0 ? (
        // TAMPILAN JIKA KOSONG (Akan muncul setelah pembayaran sukses & modal ditutup)
        <motion.div 
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="p-10 text-center text-white bg-gray-800 rounded-xl border border-gray-700"
        >
            <div className="text-6xl mb-4">🛒</div>
            <h2 className="text-xl font-bold mb-2">Keranjang Anda Kosong</h2>
            <p className="text-gray-400">Anda baru saja berbelanja atau belum menambahkan buku.</p>
        </motion.div>
      ) : (
        <motion.div className="space-y-4" variants={listVariants} initial="hidden" animate="visible">
          {cart.map((item) => (
            <motion.div key={item.id} variants={itemVariants} className="p-4 bg-gray-800 rounded-xl flex items-center justify-between border border-gray-700">
              <div className="flex items-center gap-4">
                <img src={item.cover} alt={item.title} className="w-16 h-24 object-cover rounded" />
                <div>
                  <div className="font-semibold text-white">{item.title}</div>
                  <div className="text-sm text-gray-400">{item.author}</div>
                </div>
              </div>
              <div className="text-right text-white">
                <div>Qty: {item.qty}</div>
                <div className="font-semibold">Rp {(item.price * item.qty).toLocaleString("id-ID")}</div>
                <button onClick={() => remove(item.id)} className="mt-2 text-xs text-red-400 hover:text-red-300 underline">Hapus</button>
              </div>
            </motion.div>
          ))}
          
          <div className="p-6 bg-gray-800 rounded-xl border border-gray-700 sticky bottom-4 shadow-xl z-0">
             <div className="flex justify-between items-center mb-4 text-white">
                <span className="text-lg">Total</span>
                <span className="text-2xl font-bold">Rp {total.toLocaleString("id-ID")}</span>
             </div>
             <button onClick={handleCheckout} className="w-full py-3 bg-green-600 hover:bg-green-700 text-white font-bold rounded-xl shadow-lg transition-transform active:scale-95">
                Checkout / Bayar
             </button>
          </div>
        </motion.div>
      )}
    </section>
  );
}
