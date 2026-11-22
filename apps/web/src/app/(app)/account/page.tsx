import { signatureReuseMode } from '@/lib/saved-signature'
import { getGeneratedValueTranslations, getGeneratedTranslations } from '@/i18n/generated.server'
import { GeneratedValue } from '@/i18n/generated'
import { getTranslations } from 'next-intl/server'
import { eq } from 'drizzle-orm'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, PageHeader } from '@beaconhs/ui'
import { db, withSuperAdmin } from '@beaconhs/db'
import { attachments, people, users } from '@beaconhs/db/schema'
import { attachmentUrl } from '@/lib/attachment-url'
import { requireRequestContext } from '@/lib/auth'
import { PageContainer } from '@/components/page-layout'
import { ProfileForm } from './_profile-form'
import { SignatureSection } from './_signature-section'

export async function generateMetadata() {
  const tGenerated = await getGeneratedTranslations()
  return { title: tGenerated('m_1cc23a3583b150') }
}
export const dynamic = 'force-dynamic'

export default async function AccountPage() {
  const tGeneratedValue = await getGeneratedValueTranslations()
  const ctx = await requireRequestContext()
  const t = await getTranslations('Account')

  // `users` is global (not tenant-scoped) — read on the super pool, like every
  // other identity read in getRequestContext / the platform user surfaces.
  const [account] = await withSuperAdmin(db, (tx) =>
    tx
      .select({
        name: users.name,
        email: users.email,
        timezone: users.timezone,
      })
      .from(users)
      .where(eq(users.id, ctx.userId))
      .limit(1),
  )
  if (!account) return null

  // The signature lives on the linked person record. Read it (tenant-scoped) so
  // the account page can show the current one and let the user redraw it.
  const signatureRow = ctx.personId
    ? await ctx.db(async (tx) => {
        const [row] = await tx
          .select({ id: attachments.id, metadata: people.metadata })
          .from(people)
          .leftJoin(attachments, eq(attachments.id, people.signatureAttachmentId))
          .where(eq(people.id, ctx.personId!))
          .limit(1)
        return row ?? null
      })
    : null
  const signatureUrl = signatureRow?.id ? attachmentUrl(signatureRow.id) : null

  // Password lokal dimatikan total (PM-HSE-0001): kredensial dikelola di
  // Nathara IdP (SSO). Kartu password diganti pemberitahuan statis di bawah.

  return (
    <PageContainer>
      <div className="mx-auto w-full max-w-2xl space-y-6">
        <PageHeader
          title={tGeneratedValue(t('title'))}
          description={tGeneratedValue(t('description'))}
        />

        <Card>
          <CardHeader>
            <CardTitle>
              <GeneratedValue value={t('profile')} />
            </CardTitle>
            <CardDescription>
              <GeneratedValue value={t('profileDescription')} />
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ProfileForm
              name={account.name}
              email={account.email}
              timezone={account.timezone}
              localeOverride={ctx.localeOverride}
              defaultLocale={ctx.defaultLocale}
              enabledLocales={ctx.enabledLocales}
              canOverrideLocale={ctx.membership !== null}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              <GeneratedValue value={t('signature')} />
            </CardTitle>
            <CardDescription>
              <GeneratedValue value={t('signatureDescription')} />
            </CardDescription>
          </CardHeader>
          <CardContent>
            <SignatureSection
              currentUrl={signatureUrl}
              linked={ctx.personId != null}
              reuseMode={signatureReuseMode(signatureRow?.metadata.signatureReuseMode)}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              <GeneratedValue value={t('password')} />
            </CardTitle>
            <CardDescription>
              <GeneratedValue value="Passwords are managed in Nathara SSO, not in this app. Use your identity provider to change or reset your password." />
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    </PageContainer>
  )
}
