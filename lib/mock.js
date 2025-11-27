// =========================================
// 1. DATA BUKU (15 Item)
// =========================================
export const books = [
  // --- BUKU LAMA (b1-b5) ---
  {
    id: 'b1',
    title: 'How Innovation Works',
    author: 'Matt Ridley',
    price: 120000,
    discount: 10,
    cover: 'https://cdn.gramedia.com/uploads/picture_meta/2023/5/26/uwuojnsnsdhxfgtaztmu7x.jpg',
    tags: ['business', 'innovation'],
    description: 'Eksplorasi mendalam tentang bagaimana inovasi terjadi bukan karena perintah, melainkan melalui kebebasan dan kolaborasi.',
    isbn: '978-0-00-833277-7',
    publisher: 'HarperCollins',
    pages: 416,
    weight: 0.55
  },
  {
    id: 'b2',
    title: 'Zero to One',
    author: 'Peter Thiel',
    price: 150000,
    discount: 0,
    cover: 'https://gpu.id/data-gpu/images/uploads/book/6cb2696cebc9dee871f57063ba1290b7.jpg',
    tags: ['startup', 'business'],
    description: 'Buku legendaris tentang cara membangun masa depan startup dan menciptakan sesuatu yang benar-benar baru (dari 0 ke 1).',
    isbn: '978-0-8041-3929-8',
    publisher: 'Crown Business',
    pages: 224,
    weight: 0.35
  },
  {
    id: 'b3',
    title: 'Psychology of Money',
    author: 'Morgan Housel',
    price: 90000,
    discount: 20,
    cover: 'https://cdn.gramedia.com/uploads/picture_meta/2024/1/20/qvjtc65vbzmexfegzrgs7u.jpg',
    tags: ['finance', 'self-help'],
    description: 'Pelajaran abadi mengenai kekayaan, ketamakan, dan kebahagiaan—bahwa mengelola uang bukan hanya soal logika, tapi juga perilaku.',
    isbn: '978-0-85719-768-9',
    publisher: 'Harriman House',
    pages: 252,
    weight: 0.40
  },
  {
    id: 'b4',
    title: 'Milk and Honey',
    author: 'Rupi Kaur',
    price: 200000,
    discount: 0,
    cover: 'https://www.gramedia.com/blog/content/images/2022/05/milk-and-honey.jpg',
    tags: ['poetry', 'literature'],
    description: 'Koleksi puisi dan prosa #1 New York Times Bestseller tentang pengalaman kekerasan, pelecehan, cinta, kehilangan, dan kesembuhan.',
    isbn: '978-1-4494-7425-6',
    publisher: 'Andrews McMeel',
    pages: 208,
    weight: 0.30
  },
  {
    id: 'b5',
    title: 'Desain UI/UX untuk Web',
    author: 'Jubilee Enterprise',
    price: 110000,
    discount: 15,
    cover: 'https://image.gramedia.net/rs:fit:0:0/plain/https://cdn.gramedia.com/uploads/products/-391t2araa.jpg',
    tags: ['design', 'uiux'],
    description: 'Panduan praktis untuk pemula yang ingin menguasai prinsip desain antarmuka (UI) dan pengalaman pengguna (UX) modern.',
    isbn: '978-602-04-9686-3',
    publisher: 'Elex Media',
    pages: 180,
    weight: 0.25
  },

  // --- BUKU BARU (b6-b15) ---
  {
    id: 'b6',
    title: 'Atomic Habits',
    author: 'James Clear',
    price: 180000,
    discount: 5,
    cover: 'https://images.unsplash.com/photo-1589829085413-56de8ae18c73?w=500&auto=format&fit=crop&q=60',
    tags: ['self-help', 'business'],
    description: 'Perubahan kecil yang memberikan hasil luar biasa. Cara mudah dan terbukti untuk membentuk kebiasaan baik dan menghilangkan kebiasaan buruk.',
    isbn: '978-0-7352-1129-2',
    publisher: 'Penguin Random House',
    pages: 320,
    weight: 0.50
  },
  {
    id: 'b7',
    title: 'The Lean Startup',
    author: 'Eric Ries',
    price: 145000,
    discount: 0,
    cover: 'https://images.unsplash.com/photo-1556761175-5973dc0f32e7?w=500&auto=format&fit=crop&q=60',
    tags: ['startup', 'business'],
    description: 'Pendekatan revolusioner untuk membangun bisnis dan meluncurkan produk baru dengan lebih cepat dan efisien.',
    isbn: '978-0-307-88789-4',
    publisher: 'Currency',
    pages: 336,
    weight: 0.48
  },
  {
    id: 'b8',
    title: 'Don\'t Make Me Think',
    author: 'Steve Krug',
    price: 135000,
    discount: 10,
    cover: 'https://images.unsplash.com/photo-1586717791821-3f44a5638d28?w=500&auto=format&fit=crop&q=60',
    tags: ['design', 'uiux'],
    description: 'Buku klasik tentang usabilitas web dan antarmuka. Panduan akal sehat untuk desain web yang intuitif.',
    isbn: '978-0-321-96551-6',
    publisher: 'New Riders',
    pages: 216,
    weight: 0.38
  },
  {
    id: 'b9',
    title: 'Rich Dad Poor Dad',
    author: 'Robert T. Kiyosaki',
    price: 95000,
    discount: 25,
    cover: 'https://images.unsplash.com/photo-1565514020176-dbf2277478d3?w=500&auto=format&fit=crop&q=60',
    tags: ['finance', 'business'],
    description: 'Apa yang diajarkan orang kaya kepada anak-anak mereka tentang uang yang tidak diajarkan oleh orang miskin dan kelas menengah.',
    isbn: '978-1-61268-019-4',
    publisher: 'Plata Publishing',
    pages: 336,
    weight: 0.45
  },
  {
    id: 'b10',
    title: 'Sprint',
    author: 'Jake Knapp',
    price: 160000,
    discount: 0,
    cover: 'https://images.unsplash.com/photo-1531403009284-440f080d1e12?w=500&auto=format&fit=crop&q=60',
    tags: ['startup', 'design'],
    description: 'Cara memecahkan masalah besar dan menguji ide baru hanya dalam lima hari. Metode yang digunakan di Google Ventures.',
    isbn: '978-1-5011-4239-8',
    publisher: 'Simon & Schuster',
    pages: 288,
    weight: 0.42
  },
  {
    id: 'b11',
    title: 'Rework',
    author: 'Jason Fried & DHH',
    price: 110000,
    discount: 30,
    cover: 'https://images.unsplash.com/photo-1552664730-d307ca884978?w=500&auto=format&fit=crop&q=60',
    tags: ['business', 'startup'],
    description: 'Buku yang menghapus semua aturan bisnis tradisional. Anda tidak butuh rencana bisnis, kompetisi, atau investor.',
    isbn: '978-0-307-46374-6',
    publisher: 'Crown Currency',
    pages: 288,
    weight: 0.39
  },
  {
    id: 'b12',
    title: 'The Intelligent Investor',
    author: 'Benjamin Graham',
    price: 210000,
    discount: 0,
    cover: 'https://images.unsplash.com/photo-1611974765270-ca1258634369?w=500&auto=format&fit=crop&q=60',
    tags: ['finance', 'investment'],
    description: 'Kitab suci investasi nilai. Buku yang mengajarkan strategi investasi jangka panjang yang aman dan menguntungkan.',
    isbn: '978-0-06-055566-5',
    publisher: 'Harper Business',
    pages: 640,
    weight: 0.60
  },
  {
    id: 'b13',
    title: 'Start with Why',
    author: 'Simon Sinek',
    price: 130000,
    discount: 10,
    cover: 'https://images.unsplash.com/photo-1517245386807-bb43f82c33c4?w=500&auto=format&fit=crop&q=60',
    tags: ['business', 'leadership'],
    description: 'Bagaimana para pemimpin besar menginspirasi orang lain untuk bertindak dengan memulai dari pertanyaan "Mengapa".',
    isbn: '978-1-59184-644-4',
    publisher: 'Portfolio',
    pages: 256,
    weight: 0.36
  },
  {
    id: 'b14',
    title: 'The Design of Everyday Things',
    author: 'Don Norman',
    price: 175000,
    discount: 5,
    cover: 'https://images.unsplash.com/photo-1509343256512-d77a5cb3791b?w=500&auto=format&fit=crop&q=60',
    tags: ['design', 'psychology'],
    description: 'Prinsip dasar desain yang berpusat pada manusia. Mengapa beberapa produk mudah digunakan sementara yang lain membuat frustrasi.',
    isbn: '978-0-465-05065-9',
    publisher: 'Basic Books',
    pages: 368,
    weight: 0.52
  },
  {
    id: 'b15',
    title: 'Home Body',
    author: 'Rupi Kaur',
    price: 195000,
    discount: 0,
    cover: 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=500&auto=format&fit=crop&q=60',
    tags: ['poetry', 'literature'],
    description: 'Perjalanan reflektif melalui masa lalu, masa kini, dan potensi diri. Koleksi puisi tentang penerimaan diri dan cinta.',
    isbn: '978-1-4494-8679-2',
    publisher: 'Andrews McMeel',
    pages: 192,
    weight: 0.28
  }
];

// =========================================
// 2. DATA ULASAN
// =========================================
export const reviews = {
  b1: [
    { id: 'r1', user: 'Ani', rating: 5, text: 'Sangat membuka wawasan tentang sejarah inovasi.' },
    { id: 'r2', user: 'Bambang', rating: 4, text: 'Banyak contoh kasus nyata yang menarik.' }
  ],
  b2: [
    { id: 'r3', user: 'Dewi', rating: 5, text: 'Wajib dibaca untuk founder startup!' }
  ],
  b3: [
    { id: 'r4', user: 'Budi', rating: 5, text: 'Mengubah cara pandang saya tentang menabung.' }
  ],
  b4: [
    { id: 'r5', user: 'Citra', rating: 5, text: 'Sangat menyentuh dan estetik.' }
  ],
  b6: [
    { id: 'r6', user: 'Rina', rating: 5, text: 'Buku terbaik untuk mengubah hidup tahun ini.' }
  ],
  b9: [
    { id: 'r7', user: 'Dika', rating: 4, text: 'Konsep aset vs liabilitas dijelaskan dengan sangat simpel.' }
  ]
};

// =========================================
// 3. DATA ARTIKEL BLOG (Dengan HTML Manual)
// =========================================
export const articles = [
  {
    id: 1,
    title: "Kenapa Buku Fisik Masih Relevan di Era Digital?",
    excerpt: "Di tengah gempuran e-book dan audiobook, buku cetak ternyata memiliki pesona dan manfaat kognitif yang tak tergantikan.",
    category: "Industri",
    date: "25 Sep 2024",
    image: "https://images.unsplash.com/photo-1491841573634-28140fc7ced3?w=800&auto=format&fit=crop&q=60",
    // KONTEN DENGAN HTML MANUAL
    content: `
      <p>Di era di mana segala sesuatu menjadi digital, mulai dari pembayaran hingga pertemuan kerja, banyak yang memprediksi kematian buku fisik. Namun, data menunjukkan sebaliknya. Penjualan buku cetak tetap stabil, bahkan meningkat di kalangan Gen Z.</p>
      <br/>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">Sensasi Sentuhan dan Aroma</h3>
      <p>Tidak ada yang bisa menggantikan bau kertas baru atau suara lembaran yang dibalik. Pengalaman multisensori ini membantu otak menciptakan peta mental dari apa yang kita baca, membuat informasi lebih mudah diingat dibandingkan membaca di layar.</p>
      <br/>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">Detoks Digital</h3>
      <p>Membaca buku fisik memaksa kita untuk melepaskan diri dari notifikasi, cahaya biru layar, dan gangguan internet. Ini adalah bentuk meditasi aktif yang menurunkan tingkat stres secara signifikan.</p>
    `
  },
  {
    id: 2,
    title: "5 Kebiasaan Membaca Para CEO Sukses Dunia",
    excerpt: "Bill Gates hingga Warren Buffett menghabiskan 80% waktunya untuk membaca. Simak teknik membaca efektif ala mereka.",
    category: "Produktifitas",
    date: "22 Sep 2024",
    image: "https://images.unsplash.com/photo-1556761175-5973dc0f32e7?w=800&auto=format&fit=crop&q=60",
    content: `
      <p>Warren Buffett pernah berkata, "Bacalah 500 halaman setiap hari. Begitulah cara pengetahuan bekerja. Ia menumpuk, seperti bunga majemuk." Kebiasaan ini bukan sekadar hobi, tapi strategi bisnis.</p>
      <br/>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">1. Jadikan Prioritas</h3>
      <p>Mereka tidak "mencari waktu" untuk membaca, mereka "membuat waktu". Bill Gates selalu membawa tas buku ke mana pun ia pergi, memanfaatkan setiap jeda waktu untuk membaca.</p>
      <br/>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">2. Membaca Beragam Topik</h3>
      <p>Elon Musk membaca fiksi ilmiah, biografi, hingga buku teknik roket. Wawasan lintas disiplin inilah yang memicu inovasi besar.</p>
      <ul class="list-disc ml-6 mt-4 text-slate-700 dark:text-slate-300">
         <li>Biografi Tokoh Sejarah</li>
         <li>Fiksi Ilmiah</li>
         <li>Jurnal Sains</li>
      </ul>
    `
  },
  {
    id: 3,
    title: "Resensi: Atomic Habits - Perubahan Kecil, Dampak Besar",
    excerpt: "Bedah buku terlaris James Clear yang mengubah cara jutaan orang memandang kebiasaan dan pengembangan diri.",
    category: "Resensi",
    date: "18 Sep 2024",
    image: "https://images.unsplash.com/photo-1589829085413-56de8ae18c73?w=800&auto=format&fit=crop&q=60",
    content: `
      <p>Atomic Habits bukan sekadar buku motivasi. Ini adalah panduan teknis tentang bagaimana otak manusia memproses kebiasaan. James Clear berpendapat bahwa jika Anda ingin hasil yang lebih baik, lupakan menetapkan tujuan. Fokuslah pada sistem Anda.</p>
      <br/>

      <div class="p-4 bg-blue-50 dark:bg-slate-800 border-l-4 border-bookBlue italic mb-6">
        "You do not rise to the level of your goals. You fall to the level of your systems."
      </div>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">Aturan 1 Persen</h3>
      <p>Konsep inti buku ini adalah perbaikan 1% setiap hari. Jika Anda menjadi 1% lebih baik setiap hari selama satu tahun, Anda akan menjadi <b>37 kali lebih baik</b> pada akhirnya.</p>
    `
  },
  {
    id: 4,
    title: "Tips Membangun Kebiasaan Membaca Rutin",
    excerpt: "Sulit konsisten membaca buku? Coba terapkan teknik 'Habit Stacking' yang sederhana namun ampuh ini.",
    category: "Tips",
    date: "27 Nov 2025",
    image: "https://images.unsplash.com/photo-1506880018603-83d5b814b5a6?w=800&auto=format&fit=crop&q=60",
    content: `
      <p>Banyak orang ingin membaca lebih banyak buku, tetapi sering kali gagal karena kesibukan. Kuncinya bukan pada motivasi, tapi pada sistem.</p>
      <br/>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">Apa itu Habit Stacking?</h3>
      <p>Habit Stacking adalah teknik menumpuk kebiasaan baru di atas kebiasaan lama yang sudah kuat. Rumusnya:</p>
      
      <div class="p-4 my-4 bg-blue-50 dark:bg-slate-800 border-l-4 border-bookBlue italic text-slate-700 dark:text-slate-300">
        "Setelah saya [Kebiasaan Lama], saya akan [Membaca Buku]."
      </div>

      <p>Contohnya: "Setelah saya menyeduh kopi pagi (kebiasaan lama), saya akan membaca 2 halaman buku (kebiasaan baru)."</p>
      <br/>
      
      <h3 class="text-2xl font-serif font-bold text-slate-900 dark:text-white mb-3">Mulai Kecil</h3>
      <p>Jangan targetkan 1 buku seminggu. Targetkan 5 menit sehari. Konsistensi jauh lebih penting daripada intensitas di awal.</p>
    `
  }
];
