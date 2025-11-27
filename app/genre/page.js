// 📁 app/page.js

import GenreList from '../components/GenreList'; // <-- IMPOR KOMPONEN

// Asumsikan kode UI Rekomendasi ada di dalam fungsi HomePage
export default function HomePage() {
  return (
    <main>
      {/* ... KODE HERO SECTION (Selamat datang di Gramedia Pro) ... */}

      <section className="recommendations-section">
          <h2>Rekomendasi untuk Anda</h2>
          {/* ... KODE UNTUK MENAMPILKAN KARTU BUKU REKOMENDASI ... */}
      </section>

      {/* --- TEMPATKAN KOMPONEN GENRE DI BAWAH REKOMENDASI BUKU --- */}
      <GenreList /> 
      
      {/* ... KODE LAINNYA ... */}
    </main>
  );
}
