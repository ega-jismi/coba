import { create } from 'zustand'

const useStore = create((set) => ({
  // --- STATE GLOBAL ---
  cart: [],
  wishlist: [],
  query: '',
  selectedCategory: 'All',
  isLoggedIn: false, // <--- STATE LOGIN BARU
  
  // --- ACTIONS ---
  setQuery: (q) => set({ query: q }),
  setSelectedCategory: (category) => set({ selectedCategory: category }),
  
  // Fungsi mengubah status login (Dipanggil saat login/logout/cek cookie)
  setLoggedIn: (status) => set({ isLoggedIn: status }),

  addToCart: (book) => set((state) => {
    const exists = state.cart.find((i) => i.id === book.id)
    if (exists) {
      return { cart: state.cart.map((i) => i.id === book.id ? { ...i, qty: i.qty + 1 } : i) }
    }
    return { cart: [...state.cart, { ...book, qty: 1 }] }
  }),

  decreaseQty: (id) => set((state) => {
    const item = state.cart.find((i) => i.id === id);
    if (item.qty > 1) {
        return { cart: state.cart.map((i) => i.id === id ? { ...i, qty: i.qty - 1 } : i) }
    } else {
        return { cart: state.cart.filter((i) => i.id !== id) } 
    }
  }),

  removeFromCart: (id) => set((state) => ({ cart: state.cart.filter((i) => i.id !== id) })),
  clearCart: () => set({ cart: [] }), 

  toggleWishlist: (id) => set((state) => {
      if (state.wishlist.includes(id)) { return { wishlist: state.wishlist.filter((x) => x !== id) } }
      return { wishlist: [...state.wishlist, id] }
    }),
}))

export default useStore
