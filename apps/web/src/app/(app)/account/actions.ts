'use server'

// Self-service account actions for the signed-in user: edit profile (name, time
// zone, language) or save a signature. Password changes and reset emails are
// DISABLED — credentials live in the Nathara identity provider (SSO), not in
// this app. All are blocked while impersonating — they must never mutate the
// target's identity under the admin's hand.

import { revalidatePath } from 'next/cache'
import { getTranslations } from 'next-intl/server'
import { and, eq } from 'drizzle-orm'
import { db, withSuperAdmin } from '@beaconhs/db'
import { people, tenantUsers, users } from '@beaconhs/db/schema'
import { parseAppLocale } from '@beaconhs/i18n'
import { assertNotImpersonating } from '@beaconhs/tenant'
import { withStoredSignatureAttachment } from '@/lib/signature-storage'
import { signatureReuseMode } from '@/lib/saved-signature'
import { requireRequestContext } from '@/lib/auth'
import { recordAudit, recordAuditInTransaction } from '@/lib/audit'

type Result = { ok?: boolean; error?: string }

export async function updateProfile(_prev: Result | null, formData: FormData): Promise<Result> {
  const ctx = await requireRequestContext()
  assertNotImpersonating(ctx, 'account')
  const t = await getTranslations('Account')

  const name = String(formData.get('name') ?? '').trim()
  const timezone = String(formData.get('timezone') ?? '').trim()
  const rawLocale = String(formData.get('locale') ?? '')
  const localeOverride = rawLocale ? parseAppLocale(rawLocale) : null
  if (!name) return { error: t('nameRequired') }
  if (
    rawLocale &&
    (!localeOverride || !ctx.enabledLocales.includes(localeOverride) || !ctx.membership)
  ) {
    return { error: t('invalidLanguage') }
  }

  // A typo'd time zone silently breaks every server-rendered local-time display
  // (this is exactly the greeting bug), so reject anything Intl can't format.
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone })
  } catch {
    return { error: t('invalidTimeZone') }
  }

  // `users` is a global identity table — write it on the super pool, matching
  // how /platform/users and getRequestContext read/write it.
  const before = await withSuperAdmin(db, async (tx) => {
    const [existing] = await tx
      .select({ name: users.name, timezone: users.timezone })
      .from(users)
      .where(eq(users.id, ctx.userId))
      .limit(1)
    if (!existing) return null
    let previousLocaleOverride: string | null = null
    if (ctx.membership) {
      const [membership] = await tx
        .select({ localeOverride: tenantUsers.localeOverride })
        .from(tenantUsers)
        .where(
          and(
            eq(tenantUsers.id, ctx.membership.id),
            eq(tenantUsers.tenantId, ctx.tenantId),
            eq(tenantUsers.userId, ctx.userId),
          ),
        )
        .limit(1)
      if (!membership) return null
      previousLocaleOverride = membership.localeOverride
    }
    await tx
      .update(users)
      .set({ name, timezone, updatedAt: new Date() })
      .where(eq(users.id, ctx.userId))
    if (ctx.membership) {
      await tx
        .update(tenantUsers)
        .set({ localeOverride, updatedAt: new Date() })
        .where(eq(tenantUsers.id, ctx.membership.id))
    }
    return { ...existing, localeOverride: previousLocaleOverride }
  })
  if (!before) return { error: t('accountNotFound') }

  // `users` is the source of truth for the display name (the SSO session
  // carries its own copy; no local password/session store remains to sync).
  await recordAudit(ctx, {
    entityType: 'user',
    entityId: ctx.userId,
    action: 'update',
    summary: 'Updated own account profile',
    before,
    after: { name, timezone, localeOverride },
  })

  revalidatePath('/', 'layout')
  revalidatePath('/account')
  return { ok: true }
}

export async function changePassword(_prev: Result | null, formData: FormData): Promise<Result> {
  void formData
  // Password lokal dimatikan total (PM-HSE-0001): kredensial dikelola di
  // Nathara IdP (SSO). UI memanggil ini hanya bila komponen lama tersisa.
  return {
    error:
      'Passwords are managed in Nathara SSO, not in this app. Use your identity provider to change your password.',
  }
}

/**
 * Save the signed-in user's own signature, drawn on the account page's signature
 * pad. The signature lives on the linked person record (people.signature_attachment_id)
 * and record signatures remain immutable when the saved profile image changes.
 * Uses the same verified storage/transaction saga as record sign-offs.
 */
export async function saveMySignature(dataUrl: string): Promise<Result> {
  const ctx = await requireRequestContext()
  assertNotImpersonating(ctx, 'account')
  if (!ctx.personId) {
    return { error: 'Your login is not linked to a person record yet.' }
  }
  try {
    await withStoredSignatureAttachment(ctx, dataUrl, async (tx, attachmentId) => {
      if (!attachmentId) throw new Error('Draw your signature before saving.')
      const [person] = await tx
        .select()
        .from(people)
        .where(and(eq(people.id, ctx.personId!), eq(people.tenantId, ctx.tenantId)))
        .limit(1)
        .for('update')
      if (!person) throw new Error('Your employee record could not be found.')
      await tx
        .update(people)
        .set({ signatureAttachmentId: attachmentId })
        .where(eq(people.id, person.id))
      await recordAuditInTransaction(tx, ctx, {
        entityType: 'person',
        entityId: person.id,
        action: 'update',
        summary: 'Updated signature (self-service)',
        before: { signatureAttachmentId: person.signatureAttachmentId },
        after: { signatureAttachmentId: attachmentId },
      })
    })
  } catch {
    return { error: 'Could not save your signature. Draw it again and try saving.' }
  }
  revalidatePath('/account')
  return { ok: true }
}

/** Clear the signed-in user's own signature. */
export async function clearMySignature(): Promise<Result> {
  const ctx = await requireRequestContext()
  assertNotImpersonating(ctx, 'account')
  if (!ctx.personId) return { error: 'Your login is not linked to a person record yet.' }
  try {
    await ctx.db(async (tx) => {
      const [person] = await tx
        .select()
        .from(people)
        .where(and(eq(people.id, ctx.personId!), eq(people.tenantId, ctx.tenantId)))
        .limit(1)
        .for('update')
      if (!person) throw new Error('Your employee record could not be found.')
      await tx
        .update(people)
        .set({
          signatureAttachmentId: null,
          metadata: { ...person.metadata, signatureReuseMode: 'off' },
        })
        .where(eq(people.id, person.id))
      await recordAuditInTransaction(tx, ctx, {
        entityType: 'person',
        entityId: person.id,
        action: 'update',
        summary: 'Cleared signature (self-service)',
        before: { signatureAttachmentId: person.signatureAttachmentId },
        after: { signatureAttachmentId: null, signatureReuseMode: 'off' },
      })
    })
  } catch {
    return { error: 'Could not clear your signature. Try again.' }
  }
  revalidatePath('/account')
  return { ok: true }
}

/**
 * Set/reset password via email — DINONAKTIFKAN. Kredensial dikelola di Nathara
 * IdP (SSO); tidak ada token reset yang diterbitkan aplikasi ini.
 */
export async function sendPasswordResetEmail(): Promise<Result> {
  return {
    error:
      'Passwords are managed in Nathara SSO, not in this app. Use your identity provider to reset your password.',
  }
}

/** Personal consent, isolated from managers editing employee settings. */
export async function saveMySignatureReuseMode(value: string): Promise<Result> {
  const ctx = await requireRequestContext()
  assertNotImpersonating(ctx, 'account')
  if (!ctx.personId) return { error: 'Your login is not linked to a person record yet.' }
  if (!['off', 'manual', 'automatic'].includes(value))
    return { error: 'Choose a saved signature setting.' }
  try {
    return await ctx.db(async (tx) => {
      const [person] = await tx
        .select()
        .from(people)
        .where(and(eq(people.id, ctx.personId!), eq(people.tenantId, ctx.tenantId)))
        .limit(1)
        .for('update')
      if (!person) return { error: 'Your employee record could not be found.' }
      if (value !== 'off' && !person.signatureAttachmentId)
        return { error: 'Save your signature before enabling reuse.' }
      await tx
        .update(people)
        .set({ metadata: { ...person.metadata, signatureReuseMode: value } })
        .where(eq(people.id, person.id))
      await recordAuditInTransaction(tx, ctx, {
        entityType: 'person',
        entityId: person.id,
        action: 'update',
        summary: 'Changed own saved signature reuse',
        before: { signatureReuseMode: signatureReuseMode(person.metadata.signatureReuseMode) },
        after: { signatureReuseMode: value },
      })
      revalidatePath('/account')
      return { ok: true }
    })
  } catch {
    return { error: 'Could not save signature settings.' }
  }
}
