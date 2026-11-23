import { GeneratedValue } from '@/i18n/generated'
import { getGeneratedTranslations } from '@/i18n/generated.server'
import { redirect } from 'next/navigation'
import { Alert, AlertDescription, Button } from '@beaconhs/ui'
import { Logo } from '@/components/brand-logo'
import { getCurrentUserId } from '@/lib/auth'
import { authContinuationPath, authReturnPath } from '@/lib/auth-return-path'
import { pickString } from '@/lib/list-params'

export async function generateMetadata() {
  const tGenerated = await getGeneratedTranslations()
  return { title: tGenerated('m_06c53a8bd3e768') }
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  const sp = await searchParams
  const continueHref = authContinuationPath(pickString(sp.next))
  const userId = await getCurrentUserId()
  if (userId) redirect(continueHref as any)
  const ssoUnavailable = sp.sso === 'unavailable'
  const returnPath = authReturnPath(pickString(sp.next)) ?? ''
  return (
    <main className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <Logo animated className="mx-auto h-11 w-auto" />
          <h1 className="mt-5 text-xl font-semibold">
            <GeneratedValue value="Sign in to Nathara HSE" />
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            <GeneratedValue value="Use your Nathara work account (SSO) to continue." />
          </p>
        </div>
        {ssoUnavailable ? (
          <Alert variant="destructive">
            <AlertDescription>
              <GeneratedValue value="Nathara SSO is temporarily unavailable. Please try again later." />
            </AlertDescription>
          </Alert>
        ) : null}
        <form method="GET" action="/api/auth/sso/login">
          {returnPath ? <input type="hidden" name="next" value={returnPath} /> : null}
          <Button type="submit" className="w-full">
            <GeneratedValue value="Sign in with Nathara SSO" />
          </Button>
        </form>
        <p className="text-center text-xs text-slate-500">
          <GeneratedValue value="Need an account? Contact your administrator." />
        </p>
      </div>
    </main>
  )
}
