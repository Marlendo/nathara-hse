import 'server-only'

import { createInviteGrant, inviteCallbackPath } from '@beaconhs/auth/invites'
import { enqueueEmail } from '@beaconhs/jobs'
import { appBaseUrl } from './app-base-url'

type MembershipInviteEmail = {
  membershipId: string
  tenantId: string
  tenantName: string
  userId: string
  email: string
  invitedAt: Date
  name?: string | null
}

/**
 * Kirim email undangan membership. Grant yang ditandatangani mengikat callback
 * ke tepat satu membership tertunda; aktivasi terjadi pasca-login SSO (lihat
 * `acceptInviteAfterSso`), BUKAN via magic-link token.
 */
export async function sendMembershipInviteEmail(invite: MembershipInviteEmail): Promise<void> {
  const grant = createInviteGrant({
    membershipId: invite.membershipId,
    tenantId: invite.tenantId,
    userId: invite.userId,
    invitedAt: invite.invitedAt,
  })
  const acceptUrl = `${appBaseUrl()}${inviteCallbackPath(grant)}`
  const greeting = invite.name?.trim() ? `Halo ${invite.name.trim()},\n\n` : ''
  const subject = `Anda diundang ke ${invite.tenantName} di Nathara HSE`
  const text =
    `${greeting}Anda diundang untuk bergabung ke ${invite.tenantName} di Nathara HSE.\n\n` +
    `Masuk dengan SSO Nathara lalu buka tautan ini untuk mengaktifkan keanggotaan:\n\n${acceptUrl}\n\n` +
    `Tautan undangan ini berlaku 7 hari. Jika Anda tidak mengharapkan undangan ini, abaikan email ini.`
  const html =
    `<p>${greeting ? `Halo ${escapeHtml(invite.name!.trim())},` : 'Halo,'}</p>` +
    `<p>Anda diundang untuk bergabung ke <strong>${escapeHtml(invite.tenantName)}</strong> di Nathara HSE.</p>` +
    `<p>Masuk dengan SSO Nathara lalu <a href="${escapeHtml(acceptUrl)}">buka tautan ini untuk mengaktifkan keanggotaan</a>.</p>` +
    `<p>Tautan undangan ini berlaku 7 hari.</p>`
  await enqueueEmail({
    to: invite.email,
    subject,
    html,
    text,
    meta: {
      category: 'invite',
      tenantId: invite.tenantId,
      userId: invite.userId,
    },
  })
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
