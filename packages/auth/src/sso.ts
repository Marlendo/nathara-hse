// Nathara HSE — SSO adapter STUB (fail-closed).
//
// PM-HSE-0001 / SA-HSE: login bawaan (better-auth + password lokal) dimatikan.
// Adapter final menunggu kontrak SSO prod dari PM Production:
//
//   - TODO-SSO-1 — `iss` exact, `aud` exact, JWKS URL prod exact.
//   - TODO-SSO-2 — nama klaim role + scope exact + nilai exact `admin` / `HSE`.
//   - TODO-SSO-3 — alur login yang dipakai (bentuk `/api/auth/sso/*`).
//   - TODO-SSO-4 — refresh/revoke/umur token + re-check role.
//   - TODO-SSO-5 — `publishable key` (anon key) prod.
//
// Sampai kelimanya dijawab, adapter ini MENOLAK semua verifikasi dan sesi
// (fail-closed): tidak ada tebakan `iss`/`aud`/JWKS yang di-hardcode di sini.
// Kode pemanggil (routes SSO, guard layout, halaman 403) sudah berbentuk final;
// yang belum final hanya pengisian nilai kontrak di bawah.

/** Sesi aplikasi HSE: cookie httpOnly `hse-session` (lihat SSO_SESSION_COOKIE). */
export const SSO_SESSION_COOKIE = 'hse-session'

/** Guard kanonis (FINAL): role == 'admin' AND scope == 'HSE', exact match. */
export const HSE_REQUIRED_ROLE = 'admin'
export const HSE_REQUIRED_SCOPE = 'HSE'

/**
 * Cache JWKS: hanya kunci yang di-cache, TTL 10 menit. JANGAN cache decision
 * user — setiap request verifikasi signature + expiry dari token/sesi sendiri.
 * (Efektif penuh saat TODO-SSO-1 terjawab dan fetch JWKS diimplementasikan.)
 */
export const JWKS_CACHE_TTL_MS = 10 * 60 * 1000

/** Toleransi clock-skew validasi JWT: ±60 detik. */
export const CLOCK_SKEW_S = 60

/** Umur sesi aplikasi (target, finalisasi ikut TODO-SSO-4): 12 jam. */
export const SSO_SESSION_MAX_AGE_S = 12 * 60 * 60

export const SSO_NOT_CONFIGURED_MESSAGE =
  'Login SSO Nathara belum tersedia — kontrak SSO (iss/aud/JWKS/klaim) menunggu PM Production (TODO-SSO-1..5).'

export const SSO_ACCESS_DENIED_MESSAGE =
  'Akun Anda tidak memiliki akses HSE — hubungi admin.'

export type SsoRole = string
export type SsoScope = string

export type SsoClaims = {
  /** Subject IdP (Supabase `sub`) — dipetakan ke `users.supabase_sub`. */
  sub: string
  email: string
  name?: string | null
  role: SsoRole
  scope: SsoScope
  /** Expiry epoch-detik (klaim `exp`). */
  exp: number
}

export type SsoSession = {
  /** Local `users.id` hasil provisioning SSO. */
  userId: string
  /** Subject IdP (Supabase `sub`) — dipetakan ke `users.supabase_sub`. */
  supabaseSub: string
  email: string
  name: string
  /** Nilai mapping role/scope lokal hasil provisioning. */
  role: SsoRole
  scope: SsoScope
  /**
   * Token sesi app (baris `session`) untuk pointer impersonasi. Null sampai
   * sesi app SSO final (TODO-SSO-4) — impersonasi overlay nonaktif sementara.
   */
  sessionToken?: string | null
}

export class SsoNotConfiguredError extends Error {
  constructor() {
    super(`[sso] ${SSO_NOT_CONFIGURED_MESSAGE}`)
    this.name = 'SsoNotConfiguredError'
  }
}

export class SsoAccessDeniedError extends Error {
  constructor() {
    super(`[sso] ${SSO_ACCESS_DENIED_MESSAGE}`)
    this.name = 'SsoAccessDeniedError'
  }
}

/**
 * Verifikasi JWT Supabase prod (RS256 via JWKS prod + cek `iss`/`aud`/expiry).
 *
 * STUB fail-closed: selalu menolak sampai TODO-SSO-1..5 terjawab. Implementasi
 * final: fetch JWKS → cache TTL `JWKS_CACHE_TTL_MS` → verifikasi signature +
 * expiry (±`CLOCK_SKEW_S`) → kembalikan klaim.
 */
export async function verifySupabaseJwt(_token: string): Promise<SsoClaims> {
  throw new SsoNotConfiguredError()
}

/**
 * Auto-provision: lookup `users.supabase_sub` → lookup email → tautkan
 * `supabase_sub` (sekali saja, + audit) → buat user baru HANYA bila klaim
 * memenuhi guard, else tolak 403 + audit `sso.login.denied`.
 *
 * STUB fail-closed: selalu menolak sampai kontrak SSO final.
 */
export async function provisionUser(_claims: SsoClaims): Promise<{ userId: string }> {
  throw new SsoNotConfiguredError()
}

/**
 * Baca sesi aplikasi dari cookie `hse-session`.
 *
 * STUB: tidak ada sesi yang bisa diterbitkan sebelum kontrak SSO final, jadi
 * selalu `null` (pengguna diarahkan ke `/login`). Bentuk final: verifikasi
 * sesi app (signature + expiry) lalu kembalikan `SsoSession`.
 */
export async function getSsoSession(
  _headers: Headers,
): Promise<SsoSession | null> {
  return null
}

/**
 * Guard kanonis: `role == 'admin' AND scope == 'HSE'` (exact, case-sensitive),
 * default deny 403 jelas. Dipanggil dari `getRequestContext()` pengganti dan
 * setiap route terproteksi.
 *
 * STUB fail-closed: menolak semua sesi sampai TODO-SSO-2 (nama klaim + nilai
 * exact) terjawab dan mapping lokal terisi dari provisioning SSO.
 */
export function guardAdminHse(session: SsoSession | null): asserts session is SsoSession {
  if (
    !session ||
    session.role !== HSE_REQUIRED_ROLE ||
    session.scope !== HSE_REQUIRED_SCOPE
  ) {
    throw new SsoAccessDeniedError()
  }
}

/** Hapus cookie sesi aplikasi (logout lokal; redirect logout IdP ikut TODO-SSO-4). */
export function clearSsoSessionCookie(): string {
  return `${SSO_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`
}
