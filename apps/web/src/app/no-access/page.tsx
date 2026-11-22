import { GeneratedValue } from '@/i18n/generated'
import { getGeneratedTranslations } from '@/i18n/generated.server'
import Link from 'next/link'
import { Card, CardContent } from '@beaconhs/ui'
import { Logo } from '@/components/brand-logo'
import { SSO_ACCESS_DENIED_MESSAGE } from '@beaconhs/auth/sso'

export async function generateMetadata() {
  const tGenerated = await getGeneratedTranslations()
  return { title: tGenerated('m_10dd0fc7f69dc0') }
}

// 403 kanonis guard SSO: role == 'admin' AND scope == 'HSE' tidak terpenuhi.
export default function NoAccessPage() {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-50 px-4 dark:bg-slate-950">
      <div className="w-full max-w-md space-y-5">
        <Logo className="mx-auto h-10 w-auto" />
        <Card>
          <CardContent className="space-y-4 pt-6 text-center">
            <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
              <GeneratedValue value="No access" />
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              <GeneratedValue value={SSO_ACCESS_DENIED_MESSAGE} />
            </p>
            <Link
              href="/login"
              className="inline-flex rounded-md bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-800"
            >
              <GeneratedValue value="Back to sign in" />
            </Link>
          </CardContent>
        </Card>
      </div>
    </main>
  )
}
