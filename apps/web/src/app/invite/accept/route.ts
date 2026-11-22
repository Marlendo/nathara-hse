import { appBaseUrl } from '@/lib/app-base-url'
import { NextRequest, NextResponse } from 'next/server'
import { getSsoSession } from '@beaconhs/auth'
import {
  acceptInviteAfterSso,
  inspectInviteForUser,
  type InviteAccessState,
} from '@beaconhs/auth/invites'
import { ACTIVE_ROLE_COOKIE, ACTIVE_TENANT_COOKIE } from '@/lib/auth'

export const dynamic = 'force-dynamic'

function statusRedirect(state: InviteAccessState): NextResponse {
  const url = new URL('/invite/status', appBaseUrl())
  url.searchParams.set('state', state)
  return NextResponse.redirect(url)
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  const grant = req.nextUrl.searchParams.get('grant') ?? ''
  if (!grant) return statusRedirect('invalid')

  // Undangan berjangkar SSO: sesi SSO yang memverifikasi grant mengaktifkan
  // membership tertunda (post-SSO provisioning).
  const session = await getSsoSession(req.headers).catch(() => null)
  if (!session?.userId) return statusRedirect('invalid')

  // Aktivasi idempoten: grant yang sudah dipakai / membership aktif tetap aman.
  await acceptInviteAfterSso(grant, session.userId).catch(() => null)

  const invite = await inspectInviteForUser(grant, session.userId).catch(() => null)
  if (!invite) return statusRedirect('pending')
  if (invite.state !== 'active' || !invite.tenantId) {
    return statusRedirect(invite.state)
  }

  const response = NextResponse.redirect(new URL('/dashboard', appBaseUrl()))
  response.cookies.set(ACTIVE_TENANT_COOKIE, invite.tenantId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 60 * 60 * 24 * 30,
  })
  response.cookies.delete(ACTIVE_ROLE_COOKIE)
  return response
}
