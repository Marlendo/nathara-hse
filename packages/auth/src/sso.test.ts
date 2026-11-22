import { describe, expect, it } from 'vitest'
import {
  CLOCK_SKEW_S,
  guardAdminHse,
  HSE_REQUIRED_ROLE,
  HSE_REQUIRED_SCOPE,
  JWKS_CACHE_TTL_MS,
  SsoAccessDeniedError,
  SsoNotConfiguredError,
  SSO_SESSION_COOKIE,
  clearSsoSessionCookie,
  getSsoSession,
  provisionUser,
  verifySupabaseJwt,
  type SsoSession,
} from './sso'

// Adapter SSO masih STUB fail-closed (menunggu TODO-SSO-1..5): setiap
// verifikasi/provisioning/guardsession HARUS menolak sampai kontrak final.
// Test ini mengunci perilaku fail-closed agar stub tidak lolos diam-diam.

describe('sso stub (fail-closed)', () => {
  it('menolak verifikasi JWT sampai kontrak SSO final', async () => {
    await expect(verifySupabaseJwt('header.payload.sig')).rejects.toBeInstanceOf(
      SsoNotConfiguredError,
    )
  })

  it('menolak provisioning sampai kontrak SSO final', async () => {
    await expect(
      provisionUser({
        sub: 'sub-1',
        email: 'admin@example.invalid',
        role: 'admin',
        scope: 'HSE',
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
    ).rejects.toBeInstanceOf(SsoNotConfiguredError)
  })

  it('tidak ada sesi tanpa kontrak SSO (selalu null)', async () => {
    await expect(getSsoSession(new Headers())).resolves.toBeNull()
  })

  it('guard menolak sesi kosong (default deny 403)', () => {
    expect(() => guardAdminHse(null)).toThrow(SsoAccessDeniedError)
  })

  it('guard menolak role/scope non-HSE walau sesi ada', () => {
    const base: SsoSession = {
      userId: 'u-1',
      supabaseSub: 'sub-1',
      email: 'a@example.invalid',
      name: 'A',
      role: HSE_REQUIRED_ROLE,
      scope: HSE_REQUIRED_SCOPE,
    }
    expect(() => guardAdminHse(base)).not.toThrow()
    expect(() => guardAdminHse({ ...base, role: 'viewer' })).toThrow(SsoAccessDeniedError)
    expect(() => guardAdminHse({ ...base, scope: 'OTHER' })).toThrow(SsoAccessDeniedError)
    // Exact match, case-sensitive.
    expect(() => guardAdminHse({ ...base, role: 'Admin' })).toThrow(SsoAccessDeniedError)
    expect(() => guardAdminHse({ ...base, scope: 'hse' })).toThrow(SsoAccessDeniedError)
  })

  it('mengunci konstanta desain adapter (JWKS TTL 10 mnt, skew ±60 dtk)', () => {
    expect(JWKS_CACHE_TTL_MS).toBe(10 * 60 * 1000)
    expect(CLOCK_SKEW_S).toBe(60)
    expect(HSE_REQUIRED_ROLE).toBe('admin')
    expect(HSE_REQUIRED_SCOPE).toBe('HSE')
    expect(SSO_SESSION_COOKIE).toBe('hse-session')
  })

  it('logout menghapus cookie sesi aplikasi', () => {
    const cleared = clearSsoSessionCookie()
    expect(cleared).toContain(`${SSO_SESSION_COOKIE}=`)
    expect(cleared).toContain('Max-Age=0')
    expect(cleared).toContain('HttpOnly')
  })
})
