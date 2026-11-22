'use client'

import { GeneratedValue } from '@/i18n/generated'

import { useTransition } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@beaconhs/ui'

export function SignOutButton() {
  const router = useRouter()
  const [pending, startTransition] = useTransition()
  return (
    <Button
      type="button"
      variant="outline"
      disabled={pending}
      onClick={() =>
        startTransition(async () => {
          await fetch('/api/auth/sso/logout', { method: 'POST' }).catch(() => null)
          router.replace('/login')
        })
      }
    >
      <GeneratedValue value={pending ? 'Signing out…' : 'Sign out'} />
    </Button>
  )
}
