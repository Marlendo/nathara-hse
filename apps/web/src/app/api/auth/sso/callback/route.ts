import { NextResponse } from 'next/server'
import { SSO_NOT_CONFIGURED_MESSAGE } from '@beaconhs/auth/sso'
import { authContinuationPath } from '@/lib/auth-return-path'
import { appBaseUrl } from '@/lib/app-base-url'

export const dynamic = 'force-dynamic'

/**
 * GET /api/auth/sso/callback — endpoint kembalian login SSO Nathara.
 *
 * STUB fail-closed (TODO-SSO-1..5 menunggu PM Production): selalu mengembalikan
 * pengguna ke /login dengan pemberitahuan "belum tersedia". Bentuk final:
 * tukar/terima token dari IdP prod → `verifySupabaseJwt` → `provisionUser` →
 * set cookie `hse-session` httpOnly → redirect ke `next`.
 */
export async function GET(req: Request) {
  const url = new URL(req.url)
  const next = url.searchParams.get('next') ?? undefined
  const login = new URL('/login', appBaseUrl())
  const continuation = next ? authContinuationPath(next) : null
  if (continuation) login.searchParams.set('next', continuation.replace('/auth/continue?next=', ''))
  login.searchParams.set('sso', 'unavailable')
  return NextResponse.redirect(login, { status: 303 })
}

export async function POST(req: Request) {
  return NextResponse.json({ error: SSO_NOT_CONFIGURED_MESSAGE }, { status: 503 })
}
