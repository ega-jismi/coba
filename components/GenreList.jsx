"use client"; 

import React from 'react';
import { useRouter } from "next/navigation"; 
import useStore from "../store/store";       

const genres = [
    { id: 1, name: "Business", icon: "💼" },
    { id: 2, name: "Finance", icon: "💰" },
    { id: 3, name: "Design", icon: "🎨" },
    { id: 4, name: "Startup", icon: "🚀" },
    { id: 5, name: "Poetry", icon: "🌹" },
];

const GenreList = () => {
    const router = useRouter();
    const setQuery = useStore((s) => s.setQuery);
    const setSelectedCategory = useStore((s) => s.setSelectedCategory); // <--- AMBIL DARI STORE

    const handleGenreClick = (genreName) => {
        setQuery(""); // Reset pencarian teks
        setSelectedCategory(genreName); // Set kategori global
        router.push("/katalog");
    };

    return (
        <div className="w-full py-2 bg-transparent mt-2 mb-4">
            <h3 className="text-xl font-serif font-bold text-slate-900 dark:text-white mb-3 pl-1 px-4 flex items-center gap-2 border-l-4 border-bookBlue ml-4 md:ml-0">
                ✨ Genre Pilihan
            </h3>
            
            <div className="flex gap-3 overflow-x-auto pb-2 px-1 custom-scrollbar">
                {genres.map((genre) => (
                    <div key={genre.id} className="flex-none">
                        <button 
                            onClick={() => handleGenreClick(genre.name)}
                            className="group w-[140px] h-[90px] bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700
                                       flex flex-col items-center justify-center cursor-pointer 
                                       transition-all duration-300 hover:shadow-md hover:border-bookBlue dark:hover:border-blue-500 hover:-translate-y-1"
                        >
                            <span className="text-2xl mb-2 filter group-hover:scale-110 transition-transform duration-300">
                                {genre.icon}
                            </span>
                            <span className="text-slate-600 dark:text-slate-300 text-xs font-bold group-hover:text-bookBlue dark:group-hover:text-blue-400 transition-colors">
                                {genre.name}
                            </span>
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default GenreList;
