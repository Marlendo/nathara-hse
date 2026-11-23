import { GeneratedValue } from '@/i18n/generated'
import { Logo } from './brand-logo'
import { cn } from '@beaconhs/ui'

// Header logo bersama untuk halaman auth publik (/login, /sso/link,
// /no-access, /auth/continue): wordmark NATHARA HSE + subtitle kepanjangan
// HSE tepat di bawahnya. JANGAN dipakai di sidebar/header app utama.
export function AuthBrandHeader({
  logoClassName,
  animated,
}: {
  logoClassName?: string
  animated?: boolean
}) {
  return (
    <div className="text-center">
      <Logo animated={animated} className={cn('mx-auto h-11 w-auto', logoClassName)} />
      <p className="mt-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">
        <GeneratedValue value="Health, Safety and Environment" />
      </p>
    </div>
  )
}
