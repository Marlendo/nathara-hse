import { NextResponse } from 'next/server'
import {
  auditSsoEvent,
  checkSsoRateLimit,
  clearSsoFlowCookies,
  clientIpFromHeaders,
  createSsoLinkCookie,
  createSsoSessionCookie,
  exchangeAuthCode,
  getSsoConfig,
  provisionUser,
  readSsoFlowCookies,
  SsoAccessDeniedError,
  SsoEmailLinkRequiredError,
  SsoNotConfiguredError,
  verifySupabaseJwt,
} from '@beaconhs/auth/sso'
import { timingSafeEqual } from 'node:crypto'
import { appBaseUrl } from '@/lib/app-base-url'

export const dynamic = 'force-dynamic'

function loginUnavailable(): NextResponse {
  const login = new URL('/login', appBaseUrl())
  login.searchParams.set('sso', 'unavailable')
  const response = NextResponse.redirect(login, { status: 303 })
  for (const cookie of clearSsoFlowCookies()) response.headers.append('Set-Cookie', cookie)
  return response
}

/**
 * GET /api/auth/sso/callback — endpoint kembalian login SSO Nathara.
 *
 * Path ini EXACT sesuai allowlist portal prod
 * (https://smk3.nathara.ac.id/api/auth/sso/callback) — JANGAN diubah tanpa
 * migrasi koreksi PM Production.
 *
 * Alur: validasi state → tukar code via anon key → verifikasi JWT RS256
 * (iss/aud/expiry) → guard admin/HSE → provision → cookie `hse-session`
 * → redirect `next`. Tanpa email terverifikasi → OTP-linking (/sso/link).
 */
export async function GET(req: Request) {
  const headers = req.headers
  const limit = checkSsoRateLimit(`sso-callback:${clientIpFromHeaders(headers)}`)
  if (!limit.ok) {
    return NextResponse.json(
      { error: 'Terlalu banyak percobaan. Coba lagi nanti.' },
      { status: 429, headers: { 'Retry-After': String(limit.retryAfterS) } },
    )
  }
  const url = new URL(req.url)
  if (url.searchParams.get('error')) return loginUnavailable()

  const flow = readSsoFlowCookies(headers)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  if (!flow || !code || !state) return loginUnavailable()
  const stateBuf = Buffer.from(state)
  const expectedBuf = Buffer.from(flow.state)
  if (stateBuf.length !== expectedBuf.length || !timingSafeEqual(stateBuf, expectedBuf)) {
    return loginUnavailable()
  }

  const config = getSsoConfig()
  if (!config.anonKey) return loginUnavailable()
  try {
    const exchanged = await exchangeAuthCode({
      code,
      codeVerifier: flow.verifier,
      redirectUri: config.callbackUrl,
    })
    const claims = await verifySupabaseJwt(exchanged.idToken)
    // Nonce dari login initiation tidak di-echo portal Supabase — state yang
    // mengikat (signed cookie + equality check di atas).
    const { userId } = await provisionUser({
      sub: claims.sub,
      email: exchanged.user.email || claims.email,
      name: claims.name,
      role: claims.role,
      scope: claims.scope,
    })
    const response = NextResponse.redirect(new URL(flow.next, appBaseUrl()), { status: 303 })
    response.headers.append(
      'Set-Cookie',
      createSsoSessionCookie({
        userId,
        supabaseSub: claims.sub,
        email: exchanged.user.email || claims.email,
        name: claims.name ?? '',
        role: claims.role,
        scope: claims.scope,
      }),
    )
    for (const cookie of clearSsoFlowCookies()) response.headers.append('Set-Cookie', cookie)
    return response
  } catch (err) {
    if (err instanceof SsoEmailLinkRequiredError) {
      const response = NextResponse.redirect(new URL('/sso/link', appBaseUrl()), {
        status: 303,
      })
      response.headers.append(
        'Set-Cookie',
        createSsoLinkCookie({ sub: err.sub, role: 'admin', scope: 'HSE' }),
      )
      return response
    }
    if (err instanceof SsoAccessDeniedError) {
      await auditSsoEvent({
        event: 'sso.login.denied',
        sub: err.sub ?? 'unknown',
        role: err.role,
        scope: err.scope,
        reason: err.message,
      })
      const denied = NextResponse.redirect(new URL('/no-access', appBaseUrl()), { status: 303 })
      for (const cookie of clearSsoFlowCookies()) denied.headers.append('Set-Cookie', cookie)
      return denied
    }
    if (err instanceof SsoNotConfiguredError) return loginUnavailable()
    return loginUnavailable()
  }
}

export async function POST() {
  return NextResponse.json({ error: 'Method Not Allowed' }, { status: 405 })
}
