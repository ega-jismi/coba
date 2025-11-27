"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import useStore from "../../store/store";
import { books } from "../../lib/mock"; 
import BookCard from "../../components/BookCard";
import { motion, AnimatePresence } from "framer-motion";
import { FiTrash2, FiCreditCard, FiCheckCircle, FiAlertCircle, FiShoppingCart, FiMinus, FiPlus, FiShield, FiTruck } from "react-icons/fi";

// --- UPDATE DATA PEMBAYARAN (Gabungan Data & Style) ---
const paymentMethods = [
  { id: "bca", name: "BCA", type: "bank", color: "bg-blue-600" },
  { id: "bni", name: "BNI", type: "bank", color: "bg-orange-500" },
  { id: "mandiri", name: "Mandiri", type: "bank", color: "bg-yellow-600" },
  { id: "gopay", name: "GoPay", type: "ewallet", color: "bg-green-500" },
  { id: "qris", name: "QRIS", type: "qris", color: "bg-gray-800" },
];

export default function Cart() {
  const router = useRouter();
  const cart = useStore((s) => s.cart);
  const remove = useStore((s) => s.removeFromCart);
  const clearCart = useStore((s) => s.clearCart);
  
  const add = useStore((s) => s.addToCart);
  const decrease = useStore((s) => s.decreaseQty);

  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  // --- STATE PEMBAYARAN AKTIF ---
  const [selectedPayment, setSelectedPayment] = useState(paymentMethods[0].id); // Default BCA

  const [voucherCode, setVoucherCode] = useState("");
  const [discount, setDiscount] = useState(0);
  const [voucherMessage, setVoucherMessage] = useState({ type: "", text: "" });

  const subTotal = cart.reduce((sum, i) => sum + i.price * i.qty, 0);
  const grandTotal = subTotal - discount;

  const recommendations = books
    .filter(b => !cart.find(c => c.id === b.id))
    .slice(0, 4);

  const handleApplyVoucher = () => {
    if (!voucherCode) return;
    if (voucherCode.toUpperCase() === "BLOOM50") {
      if (subTotal >= 200000) {
        setDiscount(50000);
        setVoucherMessage({ type: "success", text: "Voucher BLOOM50 dipakai!" });
      } else {
        setDiscount(0);
        setVoucherMessage({ type: "error", text: "Min. belanja Rp 200.000" });
      }
    } else {
      setDiscount(0);
      setVoucherMessage({ type: "error", text: "Kode tidak valid." });
    }
  };

  const handleCheckout = () => {
    const hasToken = document.cookie.includes("token=");
    if (!hasToken) {
      setShowLoginModal(true);
    } else {
      setShowPaymentModal(true);
    }
  };

  const handlePay = () => {
    setIsProcessing(true);
    setTimeout(() => { setIsProcessing(false); setIsSuccess(true); clearCart(); }, 2000);
  };

  const closePaymentModal = () => {
    setShowPaymentModal(false); setIsSuccess(false); setIsProcessing(false); setDiscount(0); setVoucherCode("");
  };

  // Cari nama metode pembayaran yang sedang dipilih
  const activePaymentName = paymentMethods.find(p => p.id === selectedPayment)?.name;

  return (
    <section className="max-w-6xl mx-auto min-h-[60vh] py-8 px-4 md:px-6">
      <h1 className="text-3xl font-serif font-bold mb-8 text-slate-900 dark:text-white flex items-center gap-3">
        <FiShoppingCart className="text-bookBlue" /> Keranjang Belanja
      </h1>

      {cart.length === 0 ? (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-800 rounded-2xl border border-dashed border-slate-300 dark:border-slate-700 text-center shadow-sm">
            <div className="w-24 h-24 bg-slate-100 dark:bg-slate-700 rounded-full flex items-center justify-center mb-6 text-5xl">🛒</div>
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Keranjangmu Masih Kosong</h2>
            <p className="text-slate-500 dark:text-slate-400 mb-8">Yuk, isi dengan buku-buku yang menambah wawasan!</p>
            <button onClick={() => router.push("/katalog")} className="px-8 py-3 bg-bookBlue text-white font-bold rounded-xl hover:bg-blue-900 transition-colors shadow-lg">
               Mulai Belanja
            </button>
        </motion.div>
      ) : (
        <div className="grid lg:grid-cols-12 gap-8">
          
          {/* --- KIRI: LIST ITEM --- */}
          <div className="lg:col-span-8 space-y-6">
             {cart.map((item) => (
               <motion.div layout key={item.id} className="flex gap-4 p-4 bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm">
                 <img src={item.cover} alt={item.title} className="w-24 h-36 object-cover rounded-lg shadow-md" />
                 <div className="flex-1 flex flex-col justify-between py-1">
                   <div>
                     <div className="flex justify-between items-start">
                        <h3 className="font-serif font-bold text-lg text-slate-900 dark:text-white line-clamp-2">{item.title}</h3>
                        <button onClick={() => remove(item.id)} className="text-slate-400 hover:text-red-500 transition-colors"><FiTrash2 /></button>
                     </div>
                     <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{item.author}</p>
                   </div>
                   <div className="flex items-end justify-between mt-4">
                      <div className="flex items-center border border-slate-300 dark:border-slate-600 rounded-lg bg-slate-50 dark:bg-slate-900 h-9">
                        <button onClick={() => decrease(item.id)} className="px-3 text-slate-500 hover:text-bookBlue"><FiMinus size={14}/></button>
                        <span className="w-8 text-center text-sm font-bold text-slate-900 dark:text-white">{item.qty}</span>
                        <button onClick={() => add(item)} className="px-3 text-slate-500 hover:text-bookBlue"><FiPlus size={14}/></button>
                      </div>
                      <div className="text-right">
                         <div className="text-xs text-slate-400">Total Harga</div>
                         <div className="text-lg font-bold text-bookOrange">Rp {(item.price * item.qty).toLocaleString("id-ID")}</div>
                      </div>
                   </div>
                 </div>
               </motion.div>
             ))}

             <div className="grid grid-cols-3 gap-4 mt-6 p-4 bg-blue-50 dark:bg-slate-800/50 rounded-xl border border-blue-100 dark:border-slate-700">
                <div className="flex flex-col items-center text-center gap-2"><FiShield className="text-bookBlue w-6 h-6" /><span className="text-xs font-bold text-slate-700 dark:text-slate-300">Pembayaran Aman</span></div>
                <div className="flex flex-col items-center text-center gap-2 border-l border-blue-200 dark:border-slate-700"><FiCheckCircle className="text-green-600 w-6 h-6" /><span className="text-xs font-bold text-slate-700 dark:text-slate-300">100% Original</span></div>
                <div className="flex flex-col items-center text-center gap-2 border-l border-blue-200 dark:border-slate-700"><FiTruck className="text-orange-500 w-6 h-6" /><span className="text-xs font-bold text-slate-700 dark:text-slate-300">Kirim Cepat</span></div>
             </div>
          </div>

          {/* --- KANAN: RINGKASAN --- */}
          <div className="lg:col-span-4">
             <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-lg sticky top-24">
                <h3 className="font-serif font-bold text-xl text-slate-900 dark:text-white mb-6">Ringkasan Pesanan</h3>
                
                <div className="mb-6">
                   <div className="flex gap-2">
                      <input type="text" value={voucherCode} onChange={(e) => setVoucherCode(e.target.value)} placeholder="Kode Voucher" className="flex-1 px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg bg-slate-50 dark:bg-slate-900 text-sm outline-none focus:border-bookBlue uppercase" />
                      <button onClick={handleApplyVoucher} className="px-4 py-2 bg-slate-800 dark:bg-slate-700 text-white text-sm font-bold rounded-lg hover:bg-slate-900">Pakai</button>
                   </div>
                   {voucherMessage.text && <div className={`mt-2 text-xs flex items-center gap-1 ${voucherMessage.type === "success" ? "text-green-600" : "text-red-500"}`}>{voucherMessage.type === "success" ? <FiCheckCircle /> : <FiAlertCircle />}{voucherMessage.text}</div>}
                </div>

                <div className="space-y-3 text-sm mb-6 border-t border-slate-100 dark:border-slate-700 pt-4">
                   <div className="flex justify-between text-slate-600 dark:text-slate-300"><span>Total Harga ({cart.length} barang)</span><span>Rp {subTotal.toLocaleString("id-ID")}</span></div>
                   {discount > 0 && <div className="flex justify-between text-green-600 font-bold"><span>Diskon Voucher</span><span>- Rp {discount.toLocaleString("id-ID")}</span></div>}
                   <div className="border-t border-slate-200 dark:border-slate-700 pt-4 flex justify-between items-center">
                      <span className="font-bold text-slate-900 dark:text-white">Total Tagihan</span>
                      <span className="text-2xl font-bold text-bookOrange">Rp {grandTotal.toLocaleString("id-ID")}</span>
                   </div>
                </div>

                <button onClick={handleCheckout} className="w-full py-3.5 bg-bookBlue hover:bg-blue-900 text-white font-bold rounded-xl shadow-lg transition-all flex justify-center items-center gap-2 mb-6">
                   <FiCreditCard /> Bayar Sekarang
                </button>

                {/* --- METODE PEMBAYARAN (DAPAT DIKLIK) --- */}
                <div>
                   <p className="text-xs text-center text-slate-400 mb-3">Pilih Metode Pembayaran:</p>
                   <div className="flex justify-center gap-2 flex-wrap">
                      {paymentMethods.map((m) => (
                         <button 
                            key={m.id} 
                            onClick={() => setSelectedPayment(m.id)} // Set State saat diklik
                            className={`px-3 py-1.5 rounded-lg text-[10px] font-bold text-white transition-all transform active:scale-95 border-2 
                                ${m.color} 
                                ${selectedPayment === m.id ? "ring-2 ring-offset-2 ring-bookBlue border-white scale-110" : "border-transparent opacity-70 hover:opacity-100"}`
                            }
                         >
                            {m.name}
                         </button>
                      ))}
                   </div>
                </div>
                {/* ----------------------------------------- */}

             </div>
          </div>

        </div>
      )}

      {cart.length > 0 && (
         <div className="mt-16">
            <div className="flex items-center gap-3 mb-6 border-l-4 border-bookBlue pl-4">
               <h3 className="text-2xl font-serif font-bold text-slate-900 dark:text-white">Lengkapi Koleksimu</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-6">
               {recommendations.map((b) => <BookCard key={b.id} book={b} />)}
            </div>
         </div>
      )}

      {/* MODAL LOGIN */}
      <AnimatePresence>
        {showLoginModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/70 backdrop-blur-sm">
            <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} className="bg-white dark:bg-slate-900 p-6 rounded-2xl max-w-sm w-full text-center shadow-2xl">
              <h3 className="text-xl font-bold mb-2 text-slate-900 dark:text-white">Login Dulu Yuk!</h3>
              <p className="text-gray-500 mb-6">Kamu harus masuk akun untuk melanjutkan pembayaran.</p>
              <div className="flex gap-3 justify-center">
                <button onClick={() => setShowLoginModal(false)} className="px-4 py-2 text-gray-500 hover:text-gray-700">Batal</button>
                <button onClick={() => router.push("/auth/login")} className="px-6 py-2 bg-bookBlue text-white rounded-lg">Login Sekarang</button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* MODAL PEMBAYARAN SUKSES */}
      <AnimatePresence>
        {showPaymentModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/80 backdrop-blur-sm">
            <motion.div initial={{ y: 50, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 50, opacity: 0 }} className="bg-white dark:bg-slate-900 w-full max-w-md rounded-2xl overflow-hidden shadow-2xl">
              <div className="p-4 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                <h3 className="font-bold text-lg text-slate-900 dark:text-white">Konfirmasi Pembayaran</h3>
                <button onClick={closePaymentModal}>✕</button>
              </div>
              <div className="p-6">
                {!isSuccess ? (
                  <>
                    <p className="mb-2 text-sm text-gray-500 text-center">Metode yang kamu pilih:</p>
                    
                    {/* TAMPILKAN METODE YANG DIPILIH */}
                    <div className={`mx-auto w-fit px-6 py-3 rounded-xl text-white font-bold text-xl mb-6 ${paymentMethods.find(p => p.id === selectedPayment)?.color}`}>
                       {activePaymentName}
                    </div>

                    <div className="flex justify-between font-bold text-lg mb-6 text-slate-900 dark:text-white border-t pt-4 dark:border-slate-700">
                       <span>Total Bayar</span>
                       <span className="text-bookBlue">Rp {grandTotal.toLocaleString("id-ID")}</span>
                    </div>
                    <button onClick={handlePay} disabled={isProcessing} className="w-full py-3 bg-green-600 hover:bg-green-700 text-white font-bold rounded-xl flex justify-center items-center gap-2">
                      {isProcessing ? "Memproses..." : "Konfirmasi & Bayar"}
                    </button>
                  </>
                ) : (
                  <div className="text-center py-6">
                    <div className="w-20 h-20 bg-green-100 text-green-500 rounded-full flex items-center justify-center mx-auto mb-4 text-4xl">🎉</div>
                    <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Pembayaran Berhasil!</h2>
                    <p className="text-gray-500">Terima kasih telah berbelanja di Paper Bloom.</p>
                    <button onClick={closePaymentModal} className="mt-6 px-6 py-2 bg-slate-200 dark:bg-slate-700 rounded-lg text-sm font-bold">Tutup</button>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </section>
  );
}
