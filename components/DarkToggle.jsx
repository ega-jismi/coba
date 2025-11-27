'use client'
import { useEffect, useState } from 'react'
import { FiMoon, FiSun } from 'react-icons/fi'

export default function DarkToggle(){
  const [theme, setTheme] = useState('light')

  useEffect(() => {
    // 1. Cek Local Storage atau Preferensi Sistem saat pertama load
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedTheme === 'dark' || (!savedTheme && systemPrefersDark)) {
      setTheme('dark');
      document.documentElement.classList.add('dark');
    } else {
      setTheme('light');
      document.documentElement.classList.remove('dark');
    }
  }, []);

  function toggle(){
    if (theme === 'dark') {
      setTheme('light');
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    } else {
      setTheme('dark');
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    }
  }

  return (
    <button 
      onClick={toggle} 
      aria-label="Toggle theme" 
      className="p-2 rounded-full transition-all duration-300
                 bg-gray-100 text-gray-600 hover:bg-gray-200
                 dark:bg-slate-700 dark:text-yellow-400 dark:hover:bg-slate-600"
    >
      {theme === 'dark' ? <FiSun className="w-5 h-5" /> : <FiMoon className="w-5 h-5" />}
    </button>
  )
}
