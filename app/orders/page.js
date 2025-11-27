"use client";

import { FiBox, FiTruck, FiCheckCircle, FiClock } from "react-icons/fi";

// Mock Data Pesanan
const orders = [
  {
    id: "PB-INV-001",
    date: "25 Nov 2025",
    status: "Dikirim",
    total: 216000,
    items: [
      { title: "Atomic Habits", cover: "https://images.unsplash.com/photo-1589829085413-56de8ae18c73?w=100" },
      { title: "Zero to One", cover: "https://gpu.id/data-gpu/images/uploads/book/6cb2696cebc9dee871f57063ba1290b7.jpg" }
    ]
  },
  {
    id: "PB-INV-002",
    date: "10 Nov 2025",
    status: "Selesai",
    total: 95000,
    items: [
      { title: "Rich Dad Poor Dad", cover: "https://images.unsplash.com/photo-1565514020176-dbf2277478d3?w=100" }
    ]
  }
];

export default function OrdersPage() {
  const getStatusColor = (status) => {
    switch(status) {
        case "Selesai": return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
        case "Dikirim": return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
        default: return "bg-yellow-100 text-yellow-700";
    }
  };

  const getStatusIcon = (status) => {
    switch(status) {
        case "Selesai": return <FiCheckCircle />;
        case "Dikirim": return <FiTruck />;
        default: return <FiClock />;
    }
  };

  return (
    <section className="max-w-4xl mx-auto min-h-screen pb-10">
      <h1 className="text-3xl font-serif font-bold text-slate-900 dark:text-white mb-8 border-b pb-4 border-slate-200 dark:border-slate-700">
        Riwayat Pesanan
      </h1>

      <div className="space-y-6">
        {orders.map((order) => (
            <div key={order.id} className="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm">
                {/* Header Pesanan */}
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4 pb-4 border-b border-slate-100 dark:border-slate-700">
                    <div>
                        <p className="text-xs text-slate-500 uppercase font-bold">No. Invoice</p>
                        <p className="text-lg font-bold text-slate-900 dark:text-white font-mono">{order.id}</p>
                        <p className="text-xs text-slate-400">{order.date}</p>
                    </div>
                    <div className={`mt-2 sm:mt-0 px-3 py-1 rounded-full text-xs font-bold flex items-center gap-2 ${getStatusColor(order.status)}`}>
                        {getStatusIcon(order.status)} {order.status}
                    </div>
                </div>

                {/* List Buku */}
                <div className="flex flex-col gap-3 mb-4">
                    {order.items.map((item, idx) => (
                        <div key={idx} className="flex items-center gap-4">
                            <img src={item.cover} className="w-12 h-16 object-cover rounded shadow-sm" />
                            <div>
                                <p className="text-sm font-bold text-slate-800 dark:text-slate-200">{item.title}</p>
                                <p className="text-xs text-slate-500">1 x Barang</p>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Total & Aksi */}
                <div className="flex justify-between items-center pt-4 border-t border-slate-100 dark:border-slate-700">
                    <div>
                        <p className="text-xs text-slate-500">Total Belanja</p>
                        <p className="text-lg font-bold text-bookOrange">Rp {order.total.toLocaleString("id-ID")}</p>
                    </div>
                    <button className="px-4 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm font-bold hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors">
                        Lihat Detail
                    </button>
                </div>
            </div>
        ))}
      </div>
    </section>
  );
}
