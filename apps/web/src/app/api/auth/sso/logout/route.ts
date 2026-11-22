import { NextResponse } from 'next/server'
import { clearSsoSessionCookie, SSO_SESSION_COOKIE } from '@beaconhs/auth/sso'
import { appBaseUrl } from '@/lib/app-base-url'

export const dynamic = 'force-dynamic'

/**
 * GET/POST /api/auth/sso/logout — keluar sesi aplikasi HSE (hapus cookie
 * `hse-session`). Redirect logout IdP prod ikut TODO-SSO-4.
 */
export async function GET() {
  const response = NextResponse.redirect(new URL('/login', appBaseUrl()), { status: 303 })
  response.headers.append('Set-Cookie', clearSsoSessionCookie())
  return response
}

export async function POST() {
  const response = NextResponse.json({ ok: true })
  response.cookies.delete(SSO_SESSION_COOKIE)
  return response
}
