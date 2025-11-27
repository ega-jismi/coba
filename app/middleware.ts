import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  // 1. Cek apakah user punya cookie 'token' (tanda sudah login)
  // Nanti saat login berhasil, kita harus simpan cookie ini.
  const hasToken = request.cookies.has('token');
  
  // 2. Cek apakah user sedang berada di halaman Login
  const isLoginPage = request.nextUrl.pathname.startsWith('/auth/login');

  // SKENARIO A: User belum login, tapi mencoba masuk ke halaman selain login
  // Kita paksa pindah ke /auth/login
  if (!hasToken && !isLoginPage) {
    return NextResponse.redirect(new URL('/auth/login', request.url));
  }

  // SKENARIO B: User sudah login, tapi mencoba buka halaman login lagi
  // Kita paksa pindah ke halaman utama (Dashboard/Home)
  if (hasToken && isLoginPage) {
    return NextResponse.redirect(new URL('/', request.url));
  }

  return NextResponse.next();
}

// Tentukan halaman mana saja yang dijaga oleh middleware ini
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
}