import { NextResponse } from 'next/server'
import {
  buildSsoAuthorizeUrl,
  checkSsoRateLimit,
  clientIpFromHeaders,
  createPkcePair,
  createSsoFlowCookies,
  getSsoConfig,
  SsoNotConfiguredError,
} from '@beaconhs/auth/sso'
import { randomBytes } from 'node:crypto'
import { authContinuationPath } from '@/lib/auth-return-path'
import { appBaseUrl } from '@/lib/app-base-url'
import { pickString } from '@/lib/list-params'

export const dynamic = 'force-dynamic'

/**
 * GET /api/auth/sso/login — mulai login SSO Nathara (PKCE S256).
 * Set cookie state+verifier+next (httpOnly, 10 menit) lalu redirect ke portal.
 */
export async function GET(req: Request) {
  const headers = req.headers
  const limit = checkSsoRateLimit(`sso-login:${clientIpFromHeaders(headers)}`)
  if (!limit.ok) {
    return NextResponse.json(
      { error: 'Terlalu banyak percobaan. Coba lagi nanti.' },
      { status: 429, headers: { 'Retry-After': String(limit.retryAfterS) } },
    )
  }
  let config: ReturnType<typeof getSsoConfig>
  try {
    config = getSsoConfig()
    if (!config.anonKey) throw new SsoNotConfiguredError()
  } catch {
    const login = new URL('/login', appBaseUrl())
    login.searchParams.set('sso', 'unavailable')
    return NextResponse.redirect(login, { status: 303 })
  }
  const url = new URL(req.url)
  const next = authContinuationPath(pickString(url.searchParams.get('next') ?? undefined))
  const state = randomBytes(32).toString('hex')
  const nonce = randomBytes(32).toString('hex')
  const pkce = createPkcePair()
  let authorizeUrl: string
  try {
    authorizeUrl = await buildSsoAuthorizeUrl({
      state,
      nonce,
      codeChallenge: pkce.challenge,
      redirectUri: config.callbackUrl,
    })
  } catch {
    const login = new URL('/login', appBaseUrl())
    login.searchParams.set('sso', 'unavailable')
    return NextResponse.redirect(login, { status: 303 })
  }
  const response = NextResponse.redirect(authorizeUrl, { status: 303 })
  for (const cookie of createSsoFlowCookies({ state, nonce, verifier: pkce.verifier, next })) {
    response.headers.append('Set-Cookie', cookie)
  }
  return response
}
