import { GeneratedValue } from '@/i18n/generated'
import { getGeneratedTranslations } from '@/i18n/generated.server'
import { redirect } from 'next/navigation'
import { cookies } from 'next/headers'
import { Alert, AlertDescription, Button, Card, CardContent, Input, Label } from '@beaconhs/ui'
import { Logo } from '@/components/brand-logo'
import { readSsoLinkCookie } from '@beaconhs/auth/sso'

export async function generateMetadata() {
  const tGenerated = await getGeneratedTranslations()
  return { title: tGenerated('m_172b46190b7e93') }
}

const ERROR_COPY: Record<string, string> = {
  mismatch: 'The code does not match this login attempt. Request a new code.',
  invalid: 'Something went wrong. Please try again.',
}

/**
 * /sso/link — OTP-linking: sub terverifikasi IdP belum punya email lokal.
 * Langkah 1: masukkan email → OTP dikirim via Supabase prod.
 * Langkah 2: masukkan kode OTP → sub dicocokkan → provision + sesi app.
 */
export default async function SsoLinkPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  const sp = await searchParams
  const cookieStore = await cookies()
  const pending = readSsoLinkCookie(new Headers({ cookie: cookieStore.toString() }))
  if (!pending) redirect('/login')
  const stage = sp.stage === 'code' ? 'code' : 'email'
  const errorKey = typeof sp.error === 'string' ? sp.error : null
  return (
    <main className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <Logo className="mx-auto h-11 w-auto" />
          <h1 className="mt-5 text-xl font-semibold">
            <GeneratedValue value="Link your email" />
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            <GeneratedValue value="Your Nathara account is verified. Link an email address to finish signing in to Nathara HSE." />
          </p>
        </div>
        {errorKey && ERROR_COPY[errorKey] ? (
          <Alert variant="destructive">
            <AlertDescription>
              <GeneratedValue value={ERROR_COPY[errorKey]} />
            </AlertDescription>
          </Alert>
        ) : null}
        <Card>
          <CardContent className="space-y-4 pt-6">
            <form method="POST" action="/api/auth/sso/link" className="space-y-4">
              {stage === 'email' ? (
                <>
                  <input type="hidden" name="stage" value="request" />
                  <div className="space-y-2">
                    <Label htmlFor="sso-link-email">
                      <GeneratedValue value="Work email" />
                    </Label>
                    <Input
                      id="sso-link-email"
                      name="email"
                      type="email"
                      required
                      autoComplete="email"
                    />
                  </div>
                  <Button type="submit" className="w-full">
                    <GeneratedValue value="Send verification code" />
                  </Button>
                </>
              ) : (
                <>
                  <input type="hidden" name="stage" value="verify" />
                  {pending.email ? <input type="hidden" name="email" value={pending.email} /> : null}
                  {!pending.email ? (
                    <div className="space-y-2">
                      <Label htmlFor="sso-link-email2">
                        <GeneratedValue value="Work email" />
                      </Label>
                      <Input
                        id="sso-link-email2"
                        name="email"
                        type="email"
                        required
                        autoComplete="email"
                      />
                    </div>
                  ) : null}
                  <div className="space-y-2">
                    <Label htmlFor="sso-link-code">
                      <GeneratedValue value="Verification code" />
                    </Label>
                    <Input
                      id="sso-link-code"
                      name="code"
                      inputMode="numeric"
                      required
                      autoComplete="one-time-code"
                    />
                  </div>
                  <Button type="submit" className="w-full">
                    <GeneratedValue value="Verify and sign in" />
                  </Button>
                </>
              )}
            </form>
          </CardContent>
        </Card>
      </div>
    </main>
  )
}
