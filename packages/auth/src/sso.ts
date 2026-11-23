// Nathara HSE — SSO adapter REAL (Supabase PROD IdP).
//
// Kontrak PROD FINAL (PM Production, PM-HSE-0001 lanjutan 2026-11-23):
//   - SSO_CLIENT_ID=smk3, SSO_PORTAL_URL=https://sso.nathara.ac.id
//   - JWKS_URL=https://api.nathara.ac.id/functions/v1/sso-jwks (RS256)
//   - iss exact https://sso.nathara.ac.id; aud = GAP B2 (hanya divalidasi bila
//     SSO_AUDIENCE diisi — JANGAN karang nilai)
//   - klaim `role` + `scopes` (kanonis `admin` + `HSE`, exact match)
//   - JWT TANPA email/name — provisi via sub + OTP-linking (JANGAN asumsi field
//     email pada JWT; email terverifikasi diambil dari hasil code-exchange
//     atau alur OTP Supabase, bukan dari klaim mentah)
//   - callback prod allowlist exact: https://smk3.nathara.ac.id/api/auth/sso/callback
//   - anon key (public) via file VPS: HANYA dibaca dari env saat runtime,
//     TIDAK PERNAH di-log/print/di-commit
//   - service_role DILARANG total — tidak ada referensi di file ini
//
// Desain (SA-HSE): validasi JWT RS256 via JWKS prod + cache kunci TTL 10 mnt
// (tunable SSO_JWKS_TTL_MS) + skew ±60 dtk → guard admin/HSE → auto-provision
// via users.supabase_sub → sesi app cookie hse-* (~12 jam) → logout hapus sesi
// + redirect portal. Audit sso.login.success/denied (best-effort).

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { createHash } from 'node:crypto'
import { and, eq, isNull } from 'drizzle-orm'
import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose'
import type { Database } from '@beaconhs/db'

// Klien DB dimuat LAZY (dynamic import di fungsi yang butuh) agar modul ini
// tetap dapat diuji tanpa koneksi DB; pola sama seperti lazyDatabase di
// @beaconhs/db. Di runtime Next (node) import dinamis ini normal.
async function dbKit() {
  const [{ db, withSuperAdmin }, schema] = await Promise.all([
    import('@beaconhs/db'),
    import('@beaconhs/db/schema'),
  ])
  return { db, withSuperAdmin, schema }
}
import { auditLog, tenantUsers, tenants, users } from '@beaconhs/db/schema'

/** Sesi aplikasi HSE: cookie httpOnly `hse-session` (lihat SSO_SESSION_COOKIE). */
export const SSO_SESSION_COOKIE = 'hse-session'

/** Cookie CSRF state + PKCE verifier saat inisiasi login (umur 10 menit). */
export const SSO_STATE_COOKIE = 'hse-sso-state'
export const SSO_VERIFIER_COOKIE = 'hse-sso-verifier'
/** Cookie tujuan lanjutan pasca-login (10 menit, path aman via authContinuationPath). */
export const SSO_NEXT_COOKIE = 'hse-sso-next'
/** Cookie pending OTP-linking (sub terverifikasi tanpa email, 10 menit). */
export const SSO_LINK_COOKIE = 'hse-sso-link'

/** Guard kanonis (FINAL): role == 'admin' AND scope == 'HSE', exact match. */
export const HSE_REQUIRED_ROLE = 'admin'
export const HSE_REQUIRED_SCOPE = 'HSE'

/**
 * Cache JWKS: hanya kunci yang di-cache, TTL 10 menit. JANGAN cache decision
 * user — setiap request verifikasi signature + expiry dari token/sesi sendiri.
 */
export const JWKS_CACHE_TTL_MS = 10 * 60 * 1000

/** Toleransi clock-skew validasi JWT: ±60 detik. */
export const CLOCK_SKEW_S = 60

/** Umur sesi aplikasi: 12 jam. */
export const SSO_SESSION_MAX_AGE_S = 12 * 60 * 60

/** Umur cookie sementara login/link (state, verifier, pending-link): 10 menit. */
export const SSO_FLOW_MAX_AGE_S = 10 * 60

export const SSO_NOT_CONFIGURED_MESSAGE =
  'Login SSO Nathara belum dikonfigurasi di server (kunci anon IdP hilang). Hubungi admin.'

export const SSO_ACCESS_DENIED_MESSAGE =
  'Akun Anda tidak memiliki akses HSE — hubungi admin.'

export type SsoRole = string
export type SsoScope = string

export type SsoClaims = {
  /** Subject IdP (Supabase `sub`) — dipetakan ke `users.supabase_sub`. */
  sub: string
  /** Email terverifikasi IdP — dari hasil code-exchange/OTP, BUKAN klaim JWT. */
  email: string
  name?: string | null
  role: SsoRole
  scope: SsoScope
  /** Issued-at epoch-detik (klaim `iat`). */
  iat: number
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
   * Token sesi app (baris `session`) untuk pointer impersonasi. Null untuk sesi
   * SSO stateless-HMAC — impersonasi overlay nonaktif sementara.
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
  readonly sub?: string
  readonly role?: string
  readonly scope?: string
  constructor(reason?: string, sub?: string, role?: string, scope?: string) {
    super(`[sso] ${SSO_ACCESS_DENIED_MESSAGE}${reason ? ` (${reason})` : ''}`)
    this.name = 'SsoAccessDeniedError'
    this.sub = sub
    this.role = role
    this.scope = scope
  }
}

export class SsoJwtError extends Error {
  constructor(reason: string) {
    super(`[sso] token SSO tidak valid: ${reason}`)
    this.name = 'SsoJwtError'
  }
}

export class SsoEmailLinkRequiredError extends Error {
  readonly sub: string
  constructor(sub: string) {
    super('[sso] sub terverifikasi belum punya email — lanjutkan OTP-linking')
    this.name = 'SsoEmailLinkRequiredError'
    this.sub = sub
  }
}

export class SsoOtpError extends Error {
  constructor(reason: string) {
    super(`[sso] verifikasi OTP gagal: ${reason}`)
    this.name = 'SsoOtpError'
  }
}

// ── Konfigurasi (env, tanpa nilai secret di log) ─────────────────────────────

export type SsoConfig = {
  issuer: string
  jwksUrl: string
  clientId: string
  portalUrl: string
  authorizationUrl: string | null
  tokenUrl: string | null
  callbackUrl: string
  logoutUrl: string
  audience: string
  supabaseUrl: string
  /** Anon key — dibaca HANYA di server saat runtime, jangan pernah di-log. */
  anonKey: string
  jwksTtlMs: number
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '')
}

function appBase(): string {
  return trimTrailingSlash(process.env.APP_URL ?? 'http://localhost:3000')
}

/** URL callback exact yang ter-allowlist di portal prod — WAJIB dipertahankan. */
export function ssoCallbackUrl(): string {
  const override = process.env.SSO_CALLBACK_URL?.trim()
  if (override) return override
  return `${appBase()}/api/auth/sso/callback`
}

export function getSsoConfig(): SsoConfig {
  const portalUrl = trimTrailingSlash(
    process.env.SSO_PORTAL_URL?.trim() || 'https://sso.nathara.ac.id',
  )
  const ttlRaw = Number(process.env.SSO_JWKS_TTL_MS ?? '')
  return {
    issuer: process.env.SSO_ISSUER_URL?.trim() || 'https://sso.nathara.ac.id',
    jwksUrl:
      process.env.SSO_JWKS_URL?.trim() ||
      'https://api.nathara.ac.id/functions/v1/sso-jwks',
    clientId: process.env.SSO_CLIENT_ID?.trim() || 'smk3',
    portalUrl,
    authorizationUrl: process.env.SSO_AUTHORIZATION_URL?.trim() || null,
    tokenUrl: process.env.SSO_TOKEN_URL?.trim() || null,
    callbackUrl: ssoCallbackUrl(),
    logoutUrl: process.env.SSO_LOGOUT_URL?.trim() || portalUrl,
    // GAP B2: aud hanya divalidasi bila kontrak B2 FINAL dan env diisi eksplisit.
    audience: process.env.SSO_AUDIENCE?.trim() || '',
    supabaseUrl: trimTrailingSlash(
      process.env.SUPABASE_URL?.trim() || 'https://api.nathara.ac.id',
    ),
    anonKey: process.env.SUPABASE_ANON_KEY ?? '',
    jwksTtlMs:
      Number.isSafeInteger(ttlRaw) && ttlRaw > 0 ? ttlRaw : JWKS_CACHE_TTL_MS,
  }
}

function requireAnonKey(config: SsoConfig): string {
  if (!config.anonKey) throw new SsoNotConfiguredError()
  return config.anonKey
}

// ── JWKS fetch + cache (hanya kunci, TTL tunable) ────────────────────────────

type JwksCache = { keys: { kty: string; kid?: string }[]; fetchedAt: number }

let jwksCache: JwksCache | null = null
let jwksUrlCached = ''
let jwksFailures = 0
let jwksBlockedUntil = 0

const KID_UNKNOWN_RE = /kid|JWKS|no applicable key|no matching key|key.*not found|unknown key/i
const JWKS_FETCH_FAIL_RE = /fetch failed|ECONN|ENOTFOUND|ETIMEDOUT|timeout|network/i
const JWKS_MAX_FAILURES = 3
const JWKS_COOLDOWN_MS = 30_000

/** Reset cache JWKS (untuk test). */
export function __testResetJwksCache(): void {
  jwksCache = null
  jwksUrlCached = ''
  jwksFailures = 0
  jwksBlockedUntil = 0
}

async function fetchJwksJson(jwksUrl: string): Promise<JwksCache['keys']> {
  const res = await fetch(jwksUrl, { headers: { accept: 'application/json' } })
  if (!res.ok) throw new SsoJwtError(`JWKS prod HTTP ${res.status}`)
  const data = (await res.json()) as { keys?: unknown }
  if (!data || !Array.isArray(data.keys) || data.keys.length === 0) {
    throw new SsoJwtError('JWKS prod kosong')
  }
  return data.keys as JwksCache['keys']
}

async function getJwksKeys(config: SsoConfig, forceRefresh: boolean): Promise<JwksCache['keys']> {
  if (Date.now() < jwksBlockedUntil) {
    throw new SsoJwtError('JWKS circuit terbuka — IdP tidak terjangkau')
  }
  const fresh =
    jwksCache &&
    jwksUrlCached === config.jwksUrl &&
    Date.now() - jwksCache.fetchedAt < config.jwksTtlMs
  if (fresh && !forceRefresh) return jwksCache!.keys
  try {
    const keys = await fetchJwksJson(config.jwksUrl)
    jwksCache = { keys, fetchedAt: Date.now() }
    jwksUrlCached = config.jwksUrl
    jwksFailures = 0
    jwksBlockedUntil = 0
    return keys
  } catch (err) {
    const msg = err instanceof Error ? err.message : ''
    if (JWKS_FETCH_FAIL_RE.test(msg)) {
      jwksFailures += 1
      if (jwksFailures >= JWKS_MAX_FAILURES) {
        jwksBlockedUntil = Date.now() + JWKS_COOLDOWN_MS
      }
    }
    throw err
  }
}

// ── Ekstraksi klaim role/scope — EXACT, tanpa normalisasi ─────────────────────
// Klaim kanonis prod: `role` (string) + `scopes` (array string / string
// spasi-koma). Diterima HANYA persis `admin` + `HSE`. DILARANG membaca peran
// dari lokasi klaim lain yang belum di-SSOT-kan.

export function extractRoleScope(payload: JWTPayload): { role: string; scope: string } | null {
  const role = (payload as Record<string, unknown>).role
  if (typeof role !== 'string' || role !== HSE_REQUIRED_ROLE) return null
  const scopes = (payload as Record<string, unknown>).scopes
  let scopeList: string[] = []
  if (Array.isArray(scopes)) {
    scopeList = scopes.filter((s): s is string => typeof s === 'string')
  } else if (typeof scopes === 'string') {
    scopeList = scopes.split(/[\s,]+/)
  }
  if (!scopeList.includes(HSE_REQUIRED_SCOPE)) return null
  return { role: HSE_REQUIRED_ROLE, scope: HSE_REQUIRED_SCOPE }
}

/**
 * Verifikasi JWT Supabase prod (RS256 via JWKS prod + cek `iss`/`aud`/expiry).
 * `aud` hanya dicek bila SSO_AUDIENCE diisi (GAP B2 — jangan karang nilai).
 */
export async function verifySupabaseJwt(token: string): Promise<SsoClaims> {
  const config = getSsoConfig()
  const verifyOnce = async (forceRefresh: boolean) => {
    const keys = await getJwksKeys(config, forceRefresh)
    const verifyOpts: { issuer: string; clockTolerance: number; audience?: string } = {
      issuer: config.issuer,
      clockTolerance: CLOCK_SKEW_S,
    }
    if (config.audience) verifyOpts.audience = config.audience
    const { payload } = await jwtVerify(token, createLocalJWKSet({ keys }), verifyOpts)
    return payload
  }
  let payload: JWTPayload
  try {
    payload = await verifyOnce(false)
  } catch (err) {
    const msg = err instanceof Error ? err.message : ''
    if (KID_UNKNOWN_RE.test(msg)) {
      // kid tak dikenal (rotasi 24 jam) → refetch sekali lalu coba lagi.
      try {
        payload = await verifyOnce(true)
      } catch (retryErr) {
        throw toSsoJwtError(retryErr)
      }
    } else {
      throw toSsoJwtError(err)
    }
  }
  if (typeof payload.sub !== 'string' || !payload.sub) {
    throw new SsoJwtError('klaim sub hilang')
  }
  if (typeof payload.exp !== 'number') throw new SsoJwtError('klaim exp hilang')
  const mapped = extractRoleScope(payload)
  if (!mapped) {
    throw new SsoAccessDeniedError('klaim role/scope bukan admin+HSE exact', payload.sub)
  }
  // EMAIL/NAME TIDAK ADA di JWT (kontrak B5) — jangan andalkan; pengisi
  // email terverifikasi mengikuti dari hasil code-exchange / OTP-linking.
  const rec = payload as Record<string, unknown>
  const email = typeof rec.email === 'string' ? rec.email : ''
  const name =
    (typeof rec.name === 'string' && rec.name) ||
    (typeof rec.preferred_username === 'string' && rec.preferred_username) ||
    null
  return {
    sub: payload.sub,
    email,
    name,
    role: mapped.role,
    scope: mapped.scope,
    iat: typeof payload.iat === 'number' ? payload.iat : 0,
    exp: payload.exp,
  }
}

function toSsoJwtError(err: unknown): Error {
  if (err instanceof SsoAccessDeniedError || err instanceof SsoJwtError) return err
  const msg = err instanceof Error ? err.message : String(err)
  return new SsoJwtError(msg)
}

// ── PKCE + authorize ─────────────────────────────────────────────────────────

export type PkcePair = { verifier: string; challenge: string }

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

/** Pasangan PKCE S256 (RFC 7636): verifier 64 byte acak. */
export function createPkcePair(): PkcePair {
  const verifier = base64Url(randomBytes(64))
  const challenge = base64Url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge }
}

async function resolveAuthorizationUrl(config: SsoConfig): Promise<string> {
  if (config.authorizationUrl) return config.authorizationUrl
  try {
    const res = await fetch(
      `${trimTrailingSlash(config.portalUrl)}/.well-known/openid-configuration`,
      { headers: { accept: 'application/json' } },
    )
    if (res.ok) {
      const data = (await res.json()) as { authorization_endpoint?: unknown }
      if (typeof data.authorization_endpoint === 'string' && data.authorization_endpoint) {
        return data.authorization_endpoint
      }
    }
  } catch {
    // Fallback ke path portal baku di bawah.
  }
  return `${trimTrailingSlash(config.portalUrl)}/authorize`
}

/** URL redirect login SSO (response_type=code + PKCE S256 + state + nonce). */
export async function buildSsoAuthorizeUrl(input: {
  state: string
  nonce: string
  codeChallenge: string
  redirectUri?: string
}): Promise<string> {
  const config = getSsoConfig()
  const endpoint = await resolveAuthorizationUrl(config)
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: input.redirectUri ?? config.callbackUrl,
    scope: 'openid profile email',
    state: input.state,
    nonce: input.nonce,
    code_challenge: input.codeChallenge,
    code_challenge_method: 'S256',
  })
  return `${endpoint}?${params.toString()}`
}

export type CodeExchangeResult = {
  idToken: string
  accessToken: string
  refreshToken?: string
  expiresIn?: number
  /** Identitas terverifikasi IdP dari hasil exchange (BUKAN klaim JWT). */
  user: { id: string; email: string }
}

/**
 * Tukar authorization `code` via anon key. Jalur utama: Supabase PKCE
 * (`/auth/v1/token?grant_type=pkce` + `apikey`). Bila SSO_TOKEN_URL diisi
 * eksplisit, pakai OIDC form exchange (client_id + secret opsional).
 */
export async function exchangeAuthCode(input: {
  code: string
  codeVerifier: string
  redirectUri?: string
}): Promise<CodeExchangeResult> {
  const config = getSsoConfig()
  const anonKey = requireAnonKey(config)
  const redirectUri = input.redirectUri ?? config.callbackUrl
  if (config.tokenUrl) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: redirectUri,
      client_id: config.clientId,
      code_verifier: input.codeVerifier,
    })
    const res = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    if (!res.ok) throw new SsoJwtError(`token endpoint HTTP ${res.status}`)
    const data = (await res.json()) as {
      id_token?: unknown
      access_token?: unknown
      refresh_token?: unknown
      expires_in?: unknown
    }
    if (typeof data.id_token !== 'string' || !data.id_token) {
      throw new SsoJwtError('token endpoint tanpa id_token')
    }
    const claims = await verifySupabaseJwt(data.id_token)
    return {
      idToken: data.id_token,
      accessToken: typeof data.access_token === 'string' ? data.access_token : data.id_token,
      refreshToken: typeof data.refresh_token === 'string' ? data.refresh_token : undefined,
      expiresIn: typeof data.expires_in === 'number' ? data.expires_in : undefined,
      user: { id: claims.sub, email: claims.email },
    }
  }
  const res = await fetch(
    `${config.supabaseUrl}/auth/v1/token?grant_type=pkce`,
    {
      method: 'POST',
      headers: { apikey: anonKey, 'content-type': 'application/json' },
      body: JSON.stringify({ auth_code: input.code, code_verifier: input.codeVerifier }),
    },
  )
  if (!res.ok) throw new SsoJwtError(`pertukaran code HTTP ${res.status}`)
  const data = (await res.json()) as {
    access_token?: unknown
    refresh_token?: unknown
    expires_in?: unknown
    user?: { id?: unknown; email?: unknown }
  }
  if (typeof data.access_token !== 'string' || !data.access_token) {
    throw new SsoJwtError('pertukaran code tanpa access_token')
  }
  // Access token Supabase = JWT prod (RS256, iss portal) — verifikasi penuh.
  const claims = await verifySupabaseJwt(data.access_token)
  const exchangeUser = data.user ?? {}
  const exchangeSub = typeof exchangeUser.id === 'string' ? exchangeUser.id : claims.sub
  if (exchangeSub !== claims.sub) {
    throw new SsoJwtError('sub hasil exchange tidak cocok dengan sub JWT')
  }
  const exchangeEmail = typeof exchangeUser.email === 'string' ? exchangeUser.email : ''
  return {
    idToken: data.access_token,
    accessToken: data.access_token,
    refreshToken: typeof data.refresh_token === 'string' ? data.refresh_token : undefined,
    expiresIn: typeof data.expires_in === 'number' ? data.expires_in : undefined,
    user: { id: claims.sub, email: exchangeEmail || claims.email },
  }
}

// ── OTP-linking (email BUKAN dari JWT — via Supabase Auth + anon key) ─────────
// Dipakai saat sub terverifikasi belum punya email terverifikasi lokal:
// kirim OTP ke email yang dimasukkan user → verifikasi code → user.id WAJIB
// sama dengan sub → baru provision. create_user:false (fail-closed: email yang
// tidak dikenal IdP langsung ditolak, tanpa membuat akun baru).

export async function requestEmailOtp(email: string): Promise<void> {
  const config = getSsoConfig()
  const anonKey = requireAnonKey(config)
  const normalized = email.trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    throw new SsoOtpError('format email tidak valid')
  }
  const res = await fetch(`${config.supabaseUrl}/auth/v1/otp`, {
    method: 'POST',
    headers: { apikey: anonKey, 'content-type': 'application/json' },
    body: JSON.stringify({ email: normalized, create_user: false }),
  })
  if (!res.ok) throw new SsoOtpError(`pengiriman OTP HTTP ${res.status}`)
}

export async function verifyEmailOtp(input: {
  email: string
  code: string
}): Promise<{ sub: string; email: string }> {
  const config = getSsoConfig()
  const anonKey = requireAnonKey(config)
  const normalized = input.email.trim().toLowerCase()
  const code = input.code.trim()
  if (!/^[0-9]{6,8}$/.test(code)) throw new SsoOtpError('format kode tidak valid')
  const res = await fetch(`${config.supabaseUrl}/auth/v1/verify`, {
    method: 'POST',
    headers: { apikey: anonKey, 'content-type': 'application/json' },
    body: JSON.stringify({ email: normalized, token: code, type: 'email' }),
  })
  if (!res.ok) throw new SsoOtpError(`verifikasi OTP HTTP ${res.status}`)
  const data = (await res.json()) as { user?: { id?: unknown; email?: unknown } }
  const sub = data?.user?.id
  const email = data?.user?.email
  if (typeof sub !== 'string' || !sub || typeof email !== 'string' || !email) {
    throw new SsoOtpError('respons verify tanpa user')
  }
  return { sub, email }
}

// ── Sesi aplikasi (HMAC-SHA256 + HSE_APP_SECRET, ~12 jam) ─────────────────────

function hseAppSecret(): string {
  const secret = process.env.HSE_APP_SECRET ?? ''
  if (!secret || (process.env.NODE_ENV === 'production' && secret.length < 32)) {
    throw new SsoNotConfiguredError()
  }
  return secret
}

function signPayload(payloadB64: string): string {
  return base64Url(createHmac('sha256', hseAppSecret()).update(payloadB64).digest())
}

function encodeSessionPayload(payload: Record<string, unknown>): string {
  const body = base64Url(Buffer.from(JSON.stringify(payload), 'utf8'))
  return `v1.${body}.${signPayload(body)}`
}

function decodeSessionPayload<T>(signed: string): T | null {
  const parts = signed.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1' || !parts[1] || !parts[2]) return null
  let sig: Buffer
  let expected: Buffer
  try {
    sig = Buffer.from(parts[2], 'base64url')
    expected = Buffer.from(signPayload(parts[1]), 'base64url')
  } catch {
    return null
  }
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as T
  } catch {
    return null
  }
}

/** Secure bila APP_URL https (staging/prod) — http lokal tetap bisa login. */
function useSecureCookies(): boolean {
  const appUrl = process.env.APP_URL ?? ''
  if (appUrl.startsWith('https://')) return true
  if (appUrl.startsWith('http://')) return false
  return process.env.NODE_ENV === 'production'
}

function cookieFlags(maxAgeS: number): string {
  return `Path=/; Max-Age=${maxAgeS}; HttpOnly; SameSite=Lax${useSecureCookies() ? '; Secure' : ''}`
}

/** Terbitkan cookie sesi aplikasi untuk user hasil provisioning. */
export function createSsoSessionCookie(session: Omit<SsoSession, 'sessionToken'>): string {
  const nowS = Math.floor(Date.now() / 1000)
  const value = encodeSessionPayload({
    userId: session.userId,
    supabaseSub: session.supabaseSub,
    email: session.email,
    name: session.name,
    role: session.role,
    scope: session.scope,
    iat: nowS,
    exp: nowS + SSO_SESSION_MAX_AGE_S,
  })
  return `${SSO_SESSION_COOKIE}=${value}; ${cookieFlags(SSO_SESSION_MAX_AGE_S)}`
}

/** Cookie sementara login (state + verifier + next). */
export function createSsoFlowCookies(input: {
  state: string
  nonce: string
  verifier: string
  next: string
}): string[] {
  return [
    `${SSO_STATE_COOKIE}=${encodeSessionPayload({ state: input.state, nonce: input.nonce, iat: Date.now() })}; ${cookieFlags(SSO_FLOW_MAX_AGE_S)}`,
    `${SSO_VERIFIER_COOKIE}=${encodeSessionPayload({ verifier: input.verifier, state: input.state, iat: Date.now() })}; ${cookieFlags(SSO_FLOW_MAX_AGE_S)}`,
    `${SSO_NEXT_COOKIE}=${encodeURIComponent(input.next)}; ${cookieFlags(SSO_FLOW_MAX_AGE_S)}`,
  ]
}

export function readSsoFlowCookies(headers: Headers): {
  state: string
  nonce: string
  verifier: string
  next: string
} | null {
  const jar = parseCookieHeader(headers.get('cookie'))
  const stateRaw = jar.get(SSO_STATE_COOKIE)
  const verifierRaw = jar.get(SSO_VERIFIER_COOKIE)
  if (!stateRaw || !verifierRaw) return null
  const statePayload = decodeSessionPayload<{ state: string; nonce: string; iat: number }>(stateRaw)
  const verifierPayload = decodeSessionPayload<{ verifier: string; state: string; iat: number }>(
    verifierRaw,
  )
  if (!statePayload || !verifierPayload) return null
  if (statePayload.state !== verifierPayload.state) return null
  if (Date.now() - statePayload.iat > SSO_FLOW_MAX_AGE_S * 1000) return null
  let next = '/auth/continue'
  try {
    const raw = jar.get(SSO_NEXT_COOKIE)
    if (raw) next = decodeURIComponent(raw)
  } catch {
    next = '/auth/continue'
  }
  return { state: statePayload.state, nonce: statePayload.nonce, verifier: verifierPayload.verifier, next }
}

/** Pending OTP-linking: sub terverifikasi + klaim, menunggu email via OTP. */
export function createSsoLinkCookie(input: {
  sub: string
  role: string
  scope: string
  email?: string
}): string {
  const value = encodeSessionPayload({ ...input, iat: Date.now() })
  return `${SSO_LINK_COOKIE}=${value}; ${cookieFlags(SSO_FLOW_MAX_AGE_S)}`
}

export function readSsoLinkCookie(headers: Headers): {
  sub: string
  role: string
  scope: string
  email?: string
} | null {
  const jar = parseCookieHeader(headers.get('cookie'))
  const raw = jar.get(SSO_LINK_COOKIE)
  if (!raw) return null
  const payload = decodeSessionPayload<{
    sub: string
    role: string
    scope: string
    email?: unknown
    iat: number
  }>(raw)
  if (!payload || !payload.sub) return null
  if (Date.now() - payload.iat > SSO_FLOW_MAX_AGE_S * 1000) return null
  return {
    sub: payload.sub,
    role: payload.role,
    scope: payload.scope,
    email: typeof payload.email === 'string' ? payload.email : undefined,
  }
}

export function clearSsoFlowCookies(): string[] {
  const clear = (name: string) =>
    `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${useSecureCookies() ? '; Secure' : ''}`
  return [SSO_STATE_COOKIE, SSO_VERIFIER_COOKIE, SSO_NEXT_COOKIE, SSO_LINK_COOKIE].map(clear)
}

function parseCookieHeader(header: string | null): Map<string, string> {
  const jar = new Map<string, string>()
  if (!header) return jar
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index <= 0) continue
    jar.set(part.slice(0, index).trim(), part.slice(index + 1).trim())
  }
  return jar
}

/**
 * Baca sesi aplikasi dari cookie `hse-session`: verifikasi signature HMAC +
 * expiry, lalu kembalikan `SsoSession`. Null bila tidak ada/kedaluwarsa/rusak.
 */
export async function getSsoSession(headers: Headers): Promise<SsoSession | null> {
  const jar = parseCookieHeader(headers.get('cookie'))
  const raw = jar.get(SSO_SESSION_COOKIE)
  if (!raw) return null
  let payload: {
    userId: unknown
    supabaseSub: unknown
    email: unknown
    name: unknown
    role: unknown
    scope: unknown
    iat: unknown
    exp: unknown
  } | null
  try {
    payload = decodeSessionPayload(raw)
  } catch {
    return null
  }
  if (!payload) return null
  if (
    typeof payload.userId !== 'string' ||
    typeof payload.supabaseSub !== 'string' ||
    typeof payload.email !== 'string' ||
    typeof payload.exp !== 'number'
  ) {
    return null
  }
  if (payload.exp * 1000 <= Date.now()) return null
  return {
    userId: payload.userId,
    supabaseSub: payload.supabaseSub,
    email: payload.email,
    name: typeof payload.name === 'string' ? payload.name : '',
    role: typeof payload.role === 'string' ? payload.role : '',
    scope: typeof payload.scope === 'string' ? payload.scope : '',
    sessionToken: null,
  }
}

/**
 * Guard kanonis: `role == 'admin' AND scope == 'HSE'` (exact, case-sensitive),
 * default deny 403 jelas. Dipanggil dari `getRequestContext()` pengganti dan
 * setiap route terproteksi.
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

/** Hapus cookie sesi aplikasi (logout lokal; redirect logout IdP di route). */
export function clearSsoSessionCookie(): string {
  return `${SSO_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${useSecureCookies() ? '; Secure' : ''}`
}

// ── Auto-provision (users.supabase_sub) + audit login ─────────────────────────

export type ProvisionDecision =
  | { action: 'use'; userId: string }
  | { action: 'link'; userId: string }
  | { action: 'create' }
  | { action: 'deny'; reason: string }

/**
 * Keputusan provisioning murni (tanpa IO — dapat diuji tanpa DB).
 * Prioritas: sub terikat → pakai; email terikat sub lain → tolak; email bebas
 * → tautkan sub; tanpa baris → buat baru (HANYA bila klaim admin/HSE).
 */
export function decideProvision(input: {
  sub: string
  email: string
  role: string
  scope: string
  bySub: { id: string } | null
  byEmail: { id: string; supabaseSub: string | null } | null
}): ProvisionDecision {
  if (!input.sub) return { action: 'deny', reason: 'sub kosong' }
  if (input.bySub) return { action: 'use', userId: input.bySub.id }
  const guardOk = input.role === HSE_REQUIRED_ROLE && input.scope === HSE_REQUIRED_SCOPE
  if (!guardOk) return { action: 'deny', reason: 'klaim role/scope bukan admin+HSE exact' }
  if (!input.email) return { action: 'deny', reason: 'email terverifikasi belum ada (OTP-linking)' }
  if (input.byEmail) {
    if (input.byEmail.supabaseSub && input.byEmail.supabaseSub !== input.sub) {
      return { action: 'deny', reason: 'email sudah terikat sub lain' }
    }
    if (input.byEmail.supabaseSub === input.sub) return { action: 'use', userId: input.byEmail.id }
    return { action: 'link', userId: input.byEmail.id }
  }
  return { action: 'create' }
}

export type ProvisionInput = {
  sub: string
  /** Email terverifikasi IdP (exchange/OTP) — kosong bila belum linking. */
  email: string
  name?: string | null
  role: string
  scope: string
}

async function resolveAuditTenantId(
  tx: Database,
  schema: Awaited<ReturnType<typeof dbKit>>['schema'],
  userId: string | null,
): Promise<string | null> {
  try {
    if (userId) {
      const rows = await tx
        .select({ tenantId: schema.tenantUsers.tenantId })
        .from(schema.tenantUsers)
        .where(and(eq(schema.tenantUsers.userId, userId), isNull(schema.tenantUsers.removedAt)))
        .limit(1)
      if (rows[0]) return rows[0].tenantId
    }
    const [only] = await tx.select({ id: schema.tenants.id }).from(schema.tenants).limit(1)
    return only?.id ?? null
  } catch {
    return null
  }
}

/** Audit login SSO best-effort (append-only; console fallback bila tanpa tenant). */
export async function auditSsoEvent(input: {
  event: 'sso.login.success' | 'sso.login.denied'
  sub: string
  email?: string
  userId?: string | null
  role?: string
  scope?: string
  reason?: string
}): Promise<void> {
  const detail = {
    ssoEvent: input.event,
    sub: input.sub,
    email: input.email ?? null,
    role: input.role ?? null,
    scope: input.scope ?? null,
    reason: input.reason ?? null,
  }
  try {
    const { db, withSuperAdmin, schema } = await dbKit()
    await withSuperAdmin(db, async (tx) => {
      const tenantId = await resolveAuditTenantId(tx, schema, input.userId ?? null)
      if (!tenantId) {
        console.log(`[sso-audit] ${input.event} ${JSON.stringify(detail)}`)
        return
      }
      await tx.insert(schema.auditLog).values({
        tenantId,
        actorUserId: input.userId ?? null,
        entityType: 'sso_session',
        entityId: null,
        action: 'login',
        summary:
          input.event === 'sso.login.success'
            ? `SSO login: ${input.email ?? input.sub}`
            : `SSO login ditolak: ${input.reason ?? 'guard'}`,
        metadata: detail,
      })
    })
  } catch (err) {
    console.log(
      `[sso-audit] ${input.event} ${JSON.stringify(detail)} (audit insert gagal: ${err instanceof Error ? err.message : err})`,
    )
  }
}

/**
 * Auto-provision: lookup `users.supabase_sub` → lookup email → tautkan
 * `supabase_sub` (sekali saja, + audit) → buat user baru HANYA bila klaim
 * memenuhi guard, else tolak 403 + audit `sso.login.denied`.
 *
 * Email WAJIB sudah terverifikasi IdP (dari hasil code-exchange atau OTP).
 * Tanpa email → lempar SsoEmailLinkRequiredError (rute callback mengarahkan
 * ke /sso/link). Tanpa klaim admin/HSE → SsoAccessDeniedError + audit denied.
 */
export async function provisionUser(input: ProvisionInput): Promise<{ userId: string }> {
  if (!input.sub) throw new SsoAccessDeniedError('sub kosong', input.sub)
  const { db, withSuperAdmin, schema } = await dbKit()
  const { users } = schema
  return withSuperAdmin(db, async (tx) => {
    const [bySub] = await tx
      .select({ id: users.id })
      .from(users)
      .where(eq(users.supabaseSub, input.sub))
      .limit(1)
    const [byEmail] = input.email
      ? await tx
          .select({ id: users.id, supabaseSub: users.supabaseSub })
          .from(users)
          .where(eq(users.email, input.email.trim().toLowerCase()))
          .limit(1)
      : []
    const decision = decideProvision({
      sub: input.sub,
      email: input.email.trim().toLowerCase(),
      role: input.role,
      scope: input.scope,
      bySub: bySub ?? null,
      byEmail: byEmail ?? null,
    })
    if (decision.action === 'deny') {
      const emailEmpty = !input.email.trim()
      if (emailEmpty && input.role === HSE_REQUIRED_ROLE && input.scope === HSE_REQUIRED_SCOPE) {
        throw new SsoEmailLinkRequiredError(input.sub)
      }
      throw new SsoAccessDeniedError(decision.reason, input.sub, input.role, input.scope)
    }
    if (decision.action === 'use' || decision.action === 'link') {
      if (decision.action === 'link') {
        await tx
          .update(users)
          .set({ supabaseSub: input.sub, emailVerified: true, updatedAt: new Date() })
          .where(eq(users.id, decision.userId))
      }
      const [row] = await tx
        .select({ id: users.id, email: users.email, name: users.name })
        .from(users)
        .where(eq(users.id, decision.userId))
        .limit(1)
      await auditSsoEvent({
        event: 'sso.login.success',
        sub: input.sub,
        email: row?.email ?? input.email,
        userId: decision.userId,
        role: input.role,
        scope: input.scope,
        reason: decision.action === 'link' ? 'tautkan supabase_sub sekali saja' : 'sub sudah terpetakan',
      })
      return { userId: decision.userId }
    }
    // create — HANYA klaim admin/HSE (dijamin decideProvision).
    const { randomUUID } = await import('node:crypto')
    const email = input.email.trim().toLowerCase()
    const name =
      (typeof input.name === 'string' && input.name.trim()) ||
      email.split('@')[0] ||
      'SSO User'
    try {
      const [created] = await tx
        .insert(users)
        .values({
          id: randomUUID(),
          email,
          emailVerified: true,
          name,
          supabaseSub: input.sub,
          isSuperAdmin: false,
        })
        .returning({ id: users.id })
      if (!created) throw new SsoAccessDeniedError('provisioning gagal')
      await auditSsoEvent({
        event: 'sso.login.success',
        sub: input.sub,
        email,
        userId: created.id,
        role: input.role,
        scope: input.scope,
        reason: 'auto-provision admin/HSE pertama',
      })
      return { userId: created.id }
    } catch (err) {
      if (err instanceof SsoAccessDeniedError) throw err
      // Balapanprovisioning (unique sub/email): baca ulang sekali.
      const [retry] = await tx
        .select({ id: users.id })
        .from(users)
        .where(eq(users.supabaseSub, input.sub))
        .limit(1)
      if (retry) return { userId: retry.id }
      throw err
    }
  })
}

// ── Rate limit ringan (in-memory, per instance staging) ───────────────────────

const rateBuckets = new Map<string, { count: number; resetAt: number }>()

/** Batasi percobaan SSO publik (default 10/menit per kunci). */
export function checkSsoRateLimit(
  key: string,
  max = 10,
  windowMs = 60_000,
): { ok: boolean; retryAfterS: number } {
  const now = Date.now()
  const bucket = rateBuckets.get(key)
  if (!bucket || now >= bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs })
    return { ok: true, retryAfterS: 0 }
  }
  bucket.count += 1
  if (bucket.count > max) {
    return { ok: false, retryAfterS: Math.ceil((bucket.resetAt - now) / 1000) }
  }
  return { ok: true, retryAfterS: 0 }
}

/** Reset rate-limit (untuk test). */
export function __testResetRateLimit(): void {
  rateBuckets.clear()
}

export function clientIpFromHeaders(headers: Headers): string {
  return (
    headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    headers.get('x-real-ip')?.trim() ||
    'unknown'
  )
}
