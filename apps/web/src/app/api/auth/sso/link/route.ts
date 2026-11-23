import { NextResponse } from 'next/server'
import {
  auditSsoEvent,
  checkSsoRateLimit,
  clearSsoFlowCookies,
  clientIpFromHeaders,
  createSsoLinkCookie,
  createSsoSessionCookie,
  provisionUser,
  readSsoLinkCookie,
  requestEmailOtp,
  SsoAccessDeniedError,
  SsoEmailLinkRequiredError,
  verifyEmailOtp,
} from '@beaconhs/auth/sso'
import { appBaseUrl } from '@/lib/app-base-url'

export const dynamic = 'force-dynamic'

function linkPage(error?: string): NextResponse {
  const url = new URL('/sso/link', appBaseUrl())
  url.searchParams.set('stage', 'code')
  if (error) url.searchParams.set('error', error)
  return NextResponse.redirect(url, { status: 303 })
}

/**
 * POST /api/auth/sso/link — OTP-linking untuk sub terverifikasi tanpa email.
 * Body form: stage=request {email} | stage=verify {code}.
 * Email TIDAK pernah dipercaya dari input — user.id hasil verify WAJIB sama
 * dengan sub pada pending-link cookie, baru provision + sesi app.
 */
export async function POST(req: Request) {
  const headers = req.headers
  const limit = checkSsoRateLimit(`sso-link:${clientIpFromHeaders(headers)}`, 5)
  if (!limit.ok) {
    return NextResponse.json(
      { error: 'Terlalu banyak percobaan. Coba lagi nanti.' },
      { status: 429, headers: { 'Retry-After': String(limit.retryAfterS) } },
    )
  }
  const pending = readSsoLinkCookie(headers)
  if (!pending) {
    const login = new URL('/login', appBaseUrl())
    login.searchParams.set('sso', 'unavailable')
    return NextResponse.redirect(login, { status: 303 })
  }
  let form: FormData
  try {
    form = await req.formData()
  } catch {
    return linkPage('invalid')
  }
  const stage = String(form.get('stage') ?? '')
  try {
    if (stage === 'request') {
      const email = String(form.get('email') ?? '')
        .trim()
        .toLowerCase()
      await requestEmailOtp(email)
      const next = linkPage()
      next.headers.append(
        'Set-Cookie',
        createSsoLinkCookie({ sub: pending.sub, role: pending.role, scope: pending.scope, email }),
      )
      return next
    }
    if (stage === 'verify') {
      const email = (String(form.get('email') ?? '').trim().toLowerCase() || pending.email || '')
      const code = String(form.get('code') ?? '')
      if (!email || (pending.email && pending.email !== email)) return linkPage('mismatch')
      const verified = await verifyEmailOtp({ email, code })
      if (verified.sub !== pending.sub) {
        await auditSsoEvent({
          event: 'sso.login.denied',
          sub: pending.sub,
          email,
          role: pending.role,
          scope: pending.scope,
          reason: 'OTP valid tetapi sub tidak cocok dengan pending-link',
        })
        return linkPage('mismatch')
      }
      // Klaim dari pending cookie sudah exact admin/HSE (dijamin callback);
      // verifikasi ulang murah sebelum provision.
      const { userId } = await provisionUser({
        sub: pending.sub,
        email: verified.email,
        name: null,
        role: pending.role,
        scope: pending.scope,
      })
      const response = NextResponse.redirect(new URL('/auth/continue', appBaseUrl()), {
        status: 303,
      })
      response.headers.append(
        'Set-Cookie',
        createSsoSessionCookie({
          userId,
          supabaseSub: pending.sub,
          email: verified.email,
          name: verified.email.split('@')[0] ?? '',
          role: pending.role,
          scope: pending.scope,
        }),
      )
      for (const cookie of clearSsoFlowCookies()) response.headers.append('Set-Cookie', cookie)
      return response
    }
    return linkPage('invalid')
  } catch (err) {
    if (err instanceof SsoEmailLinkRequiredError) return linkPage('invalid')
    if (err instanceof SsoAccessDeniedError) {
      await auditSsoEvent({
        event: 'sso.login.denied',
        sub: err.sub ?? pending.sub,
        role: err.role ?? pending.role,
        scope: err.scope ?? pending.scope,
        reason: err.message,
      })
      return NextResponse.redirect(new URL('/no-access', appBaseUrl()), { status: 303 })
    }
    return linkPage('invalid')
  }
}

// GET tidak dipakai (halaman /sso/link yang me-render form).
export async function GET() {
  return NextResponse.json({ error: 'Method Not Allowed' }, { status: 405 })
}
