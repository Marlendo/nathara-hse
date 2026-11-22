'use client'

import { GeneratedValue } from '@/i18n/generated'

import { useState, useTransition } from 'react'
import { useRouter } from 'next/navigation'
import { Alert, AlertDescription, Button } from '@beaconhs/ui'
import { SSO_NOT_CONFIGURED_MESSAGE } from '@beaconhs/auth/sso'

// Halaman /login ADAPT: tombol "Masuk dengan SSO Nathara" (stub, fail-closed
// 403/sso=unavailable sampai kontrak SSO TODO-SSO-1..5 datang). Form
// password + magic-link bawaan dimatikan total (K-9).

export function LoginForm({ continueHref = '/auth/continue' }: { continueHref?: string }) {
  const router = useRouter()
  const [pending, start] = useTransition()
  const [error, setError] = useState<string | null>(null)

  function onSignIn() {
    setError(null)
    start(() => {
      // Stub SSO: arahkan ke callback yang fail-closed (redirect kembali ke
      // /login?sso=unavailable). Bentuk final: redirect ke IdP Supabase prod.
      try {
        const url = `/api/auth/sso/callback?next=${encodeURIComponent(continueHref)}`
        router.push(url as any)
        // Jika kontrak belum final, callback mengembalikan ke sini — tampilkan
        // penjelas agar tidak terlihat seperti tombol mati.
        setError(SSO_NOT_CONFIGURED_MESSAGE)
      } catch {
        setError(SSO_NOT_CONFIGURED_MESSAGE)
      }
    })
  }

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault()
        onSignIn()
      }}
    >
      <GeneratedValue
        value={
          error ? (
            <Alert variant="destructive">
              <AlertDescription>
                <GeneratedValue value={error} />
              </AlertDescription>
            </Alert>
          ) : null
        }
      />

      <Button type="submit" className="w-full" disabled={pending}>
        <GeneratedValue value={pending ? 'Connecting…' : 'Sign in with Nathara SSO'} />
      </Button>
      <p className="text-center text-xs text-slate-500">
        <GeneratedValue value="Passwords are managed in the Nathara identity provider, not in this app." />
      </p>
    </form>
  )
}
