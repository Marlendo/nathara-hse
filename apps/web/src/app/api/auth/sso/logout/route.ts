import { NextResponse } from 'next/server'
import { clearSsoFlowCookies, clearSsoSessionCookie, getSsoConfig } from '@beaconhs/auth/sso'
import { appBaseUrl } from '@/lib/app-base-url'

export const dynamic = 'force-dynamic'

/**
 * GET/POST /api/auth/sso/logout — keluar sesi aplikasi HSE (hapus cookie
 * `hse-session` + cookie alur SSO) lalu redirect ke logout portal IdP.
 */
export async function GET() {
  const { logoutUrl } = getSsoConfig()
  const response = NextResponse.redirect(logoutUrl, { status: 303 })
  response.headers.append('Set-Cookie', clearSsoSessionCookie())
  for (const cookie of clearSsoFlowCookies()) response.headers.append('Set-Cookie', cookie)
  return response
}

export async function POST() {
  const { logoutUrl } = getSsoConfig()
  const response = NextResponse.json({ ok: true, redirectTo: logoutUrl })
  response.cookies.delete('hse-session')
  return response
}
