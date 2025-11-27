"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation"; 

const banners = [
  {
    id: 1,
    image: "https://images.unsplash.com/photo-1557821552-17105176677c?w=1200&auto=format&fit=crop&q=80",
    alt: "Promo Year End Sale",
    link: "/promo", 
  },
  {
    id: 2,
    image: "https://images.unsplash.com/photo-1519681393784-d8e5b5a4570e?w=1200&auto=format&fit=crop&q=80",
    alt: "Koleksi Buku Terbaru",
    link: "/detail/b6", 
  },
  {
    id: 3,
    image: "https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?w=1200&auto=format&fit=crop&q=80",
    alt: "Diskon Buku Pelajaran",
    link: "/katalog", 
  },
];

const slideVariants = {
  enter: (direction) => ({ x: direction > 0 ? 1000 : -1000, opacity: 0 }),
  center: { zIndex: 1, x: 0, opacity: 1 },
  exit: (direction) => ({ zIndex: 0, x: direction < 0 ? 1000 : -1000, opacity: 0 })
};

export default function BannerSlider() {
  const [index, setIndex] = useState(0);
  const [direction, setDirection] = useState(0);
  const [isPaused, setIsPaused] = useState(false); 
  const router = useRouter();

  const paginate = useCallback((newDirection) => {
    setDirection(newDirection);
    setIndex((prevIndex) => {
      let nextIndex = prevIndex + newDirection;
      if (nextIndex < 0) nextIndex = banners.length - 1;
      if (nextIndex >= banners.length) nextIndex = 0;
      return nextIndex;
    });
  }, []);

  useEffect(() => {
    if (isPaused) return;
    const timer = setInterval(() => { paginate(1); }, 5000);
    return () => clearInterval(timer);
  }, [isPaused, paginate]);

  const handleBannerClick = () => {
    router.push(banners[index].link);
  };

  return (
    <div 
      className="relative w-full h-[200px] sm:h-[300px] lg:h-[420px] rounded-2xl overflow-hidden shadow-lg group cursor-pointer bg-gray-900"
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      onClick={handleBannerClick}
    >
      <AnimatePresence initial={false} custom={direction}>
        <motion.img
          key={index}
          src={banners[index].image}
          alt={banners[index].alt}
          custom={direction}
          variants={slideVariants}
          initial="enter"
          animate="center"
          exit="exit"
          transition={{ x: { type: "spring", stiffness: 300, damping: 30 }, opacity: { duration: 0.2 } }}
          drag="x"
          dragConstraints={{ left: 0, right: 0 }}
          dragElastic={1}
          onDragEnd={(e, { offset, velocity }) => {
            const swipe = Math.abs(offset.x) * velocity.x;
            if (swipe < -10000) paginate(1);
            else if (swipe > 10000) paginate(-1);
          }}
          className="absolute inset-0 w-full h-full object-cover"
        />
      </AnimatePresence>

      <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent pointer-events-none" />

      <div className="absolute bottom-8 left-8 text-white z-10 pointer-events-none hidden sm:block">
         <span className="px-3 py-1 bg-bookBlue text-xs font-bold rounded-full mb-2 inline-block">Special Offer</span>
         <h2 className="text-3xl md:text-4xl font-serif font-bold drop-shadow-md">
            Diskon Hingga 70%
         </h2>
         <p className="text-sm md:text-base opacity-90 mt-1">Klik untuk lihat detail promo</p>
      </div>

      <button className="absolute left-4 top-1/2 -translate-y-1/2 z-20 p-3 bg-white/20 hover:bg-white/40 backdrop-blur rounded-full text-white opacity-0 group-hover:opacity-100 transition-opacity duration-300" onClick={(e) => { e.stopPropagation(); paginate(-1); }}>
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" /></svg>
      </button>

      <button className="absolute right-4 top-1/2 -translate-y-1/2 z-20 p-3 bg-white/20 hover:bg-white/40 backdrop-blur rounded-full text-white opacity-0 group-hover:opacity-100 transition-opacity duration-300" onClick={(e) => { e.stopPropagation(); paginate(1); }}>
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" /></svg>
      </button>

      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 flex gap-2 z-20" onClick={(e) => e.stopPropagation()}>
        {banners.map((_, idx) => (
          <button key={idx} onClick={() => { setDirection(idx > index ? 1 : -1); setIndex(idx); }} className={`w-2 h-2 rounded-full transition-all duration-300 ${idx === index ? "bg-white w-6" : "bg-white/50 hover:bg-white"}`} />
        ))}
      </div>
    </div>
  );
}
