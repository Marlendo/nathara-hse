import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import {
  auditSsoEvent,
  buildSsoAuthorizeUrl,
  checkSsoRateLimit,
  clearSsoSessionCookie,
  CLOCK_SKEW_S,
  createPkcePair,
  createSsoLinkCookie,
  createSsoSessionCookie,
  createSsoFlowCookies,
  decideProvision,
  exchangeAuthCode,
  extractRoleScope,
  getSsoConfig,
  getSsoSession,
  guardAdminHse,
  HSE_REQUIRED_ROLE,
  HSE_REQUIRED_SCOPE,
  JWKS_CACHE_TTL_MS,
  readSsoFlowCookies,
  readSsoLinkCookie,
  requestEmailOtp,
  ssoCallbackUrl,
  SSO_SESSION_COOKIE,
  SsoAccessDeniedError,
  SsoJwtError,
  SsoNotConfiguredError,
  SSO_SESSION_MAX_AGE_S,
  verifyEmailOtp,
  verifySupabaseJwt,
  __testResetJwksCache,
  __testResetRateLimit,
  type SsoSession,
} from './sso'

// Adapter SSO REAL (kontrak PROD FINAL PM-HSE-0001 2026-11-23): PKCE penuh,
// JWKS prod (mock fetch di sini), guard admin/HSE exact, sesi HMAC ~12 jam,
// OTP-linking tanpa asumsi email pada JWT. Tanpa DB/network asli.

const ISS = 'https://sso.nathara.ac.id'
const JWKS_URL = 'https://api.nathara.ac.id/functions/v1/sso-jwks'

type KeyMaterial = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  privateKey: any
  jwk: Record<string, unknown> & { kid: string }
}

async function makeKeys(kid: string): Promise<KeyMaterial> {
  const { privateKey, publicKey } = await generateKeyPair('RS256')
  const jwk = (await exportJWK(publicKey)) as Record<string, unknown> & { kid: string }
  jwk.kid = kid
  jwk.alg = 'RS256'
  jwk.use = 'sig'
  return { privateKey, jwk }
}

async function signJwt(
  key: KeyMaterial['privateKey'],
  kid: string,
  payload: Record<string, unknown> & { exp?: number },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(ISS)
    .setIssuedAt(now)
    .setExpirationTime(payload.exp ?? now + 900)
    .sign(key)
}

describe('konfigurasi SSO prod', () => {
  beforeEach(() => {
    vi.stubEnv('APP_URL', 'https://smk3.nathara.ac.id')
    vi.stubEnv('SSO_AUDIENCE', '')
  })
  afterEach(() => vi.unstubAllEnvs())

  it('mengunci konstanta desain adapter (JWKS TTL 10 mnt, skew ±60 dtk, sesi 12 jam)', () => {
    expect(JWKS_CACHE_TTL_MS).toBe(10 * 60 * 1000)
    expect(CLOCK_SKEW_S).toBe(60)
    expect(HSE_REQUIRED_ROLE).toBe('admin')
    expect(HSE_REQUIRED_SCOPE).toBe('HSE')
    expect(SSO_SESSION_COOKIE).toBe('hse-session')
    expect(SSO_SESSION_MAX_AGE_S).toBe(12 * 60 * 60)
  })

  it('memakai default kontrak prod (client smk3, iss portal, JWKS edge)', () => {
    const config = getSsoConfig()
    expect(config.clientId).toBe('smk3')
    expect(config.issuer).toBe(ISS)
    expect(config.jwksUrl).toBe(JWKS_URL)
    expect(config.supabaseUrl).toBe('https://api.nathara.ac.id')
    expect(config.audience).toBe('')
  })

  it('mempertahankan path callback exact allowlist portal', () => {
    expect(ssoCallbackUrl()).toBe('https://smk3.nathara.ac.id/api/auth/sso/callback')
  })

  it('logout menghapus cookie dengan flag Secure di APP_URL https', () => {
    const cleared = clearSsoSessionCookie()
    expect(cleared).toContain(`${SSO_SESSION_COOKIE}=`)
    expect(cleared).toContain('Max-Age=0')
    expect(cleared).toContain('HttpOnly')
    expect(cleared).toContain('SameSite=Lax')
    expect(cleared).toContain('Secure')
  })
})

describe('guard kanonis admin/HSE', () => {
  const base: SsoSession = {
    userId: 'u-1',
    supabaseSub: 'sub-1',
    email: 'a@example.invalid',
    name: 'A',
    role: HSE_REQUIRED_ROLE,
    scope: HSE_REQUIRED_SCOPE,
  }
  it('default deny 403 (null maupun klaim non-exact)', () => {
    expect(() => guardAdminHse(null)).toThrow(SsoAccessDeniedError)
    expect(() => guardAdminHse(base)).not.toThrow()
    expect(() => guardAdminHse({ ...base, role: 'viewer' })).toThrow(SsoAccessDeniedError)
    expect(() => guardAdminHse({ ...base, scope: 'OTHER' })).toThrow(SsoAccessDeniedError)
    expect(() => guardAdminHse({ ...base, role: 'Admin' })).toThrow(SsoAccessDeniedError)
    expect(() => guardAdminHse({ ...base, scope: 'hse' })).toThrow(SsoAccessDeniedError)
  })
})

describe('extractRoleScope (exact, tanpa normalisasi)', () => {
  it('menerima admin + HSE (array maupun string)', () => {
    expect(extractRoleScope({ role: 'admin', scopes: ['HSE', 'OTHER'] })).toEqual({
      role: 'admin',
      scope: 'HSE',
    })
    expect(extractRoleScope({ role: 'admin', scopes: 'HSE' })).toEqual({
      role: 'admin',
      scope: 'HSE',
    })
  })
  it('menolak nilai non-exact', () => {
    expect(extractRoleScope({ role: 'Admin', scopes: ['HSE'] })).toBeNull()
    expect(extractRoleScope({ role: 'admin', scopes: ['hse'] })).toBeNull()
    expect(extractRoleScope({ role: 'admin', scopes: ['OTHER'] })).toBeNull()
    expect(extractRoleScope({ role: 'admin' })).toBeNull()
    expect(extractRoleScope({})).toBeNull()
  })
})

describe('PKCE', () => {
  it('round-trip verifier/challenge S256', async () => {
    const { createHash } = await import('node:crypto')
    const pair = createPkcePair()
    expect(pair.verifier.length).toBeGreaterThan(40)
    const expected = createHash('sha256').update(pair.verifier).digest('base64url')
    expect(pair.challenge).toBe(expected)
  })
})

describe('verifySupabaseJwt (JWKS mock)', () => {
  let keys: KeyMaterial
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    vi.stubEnv('APP_URL', 'https://smk3.nathara.ac.id')
    vi.stubEnv('SSO_AUDIENCE', '')
    vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key')
    __testResetJwksCache()
    keys = await makeKeys('sso-test-1')
    fetchMock = vi.fn(async (url: unknown) => {
      if (String(url) === JWKS_URL) {
        return { ok: true, json: async () => ({ keys: [keys.jwk] }) } as Response
      }
      throw new Error(`unexpected fetch ${url}`)
    })
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
  })

  it('menerima JWT valid admin+HSE dan menolak selain itu', async () => {
    const good = await signJwt(keys.privateKey, 'sso-test-1', {
      sub: 'sub-1',
      role: 'admin',
      scopes: ['HSE'],
    })
    const claims = await verifySupabaseJwt(good)
    expect(claims.sub).toBe('sub-1')
    expect(claims.role).toBe('admin')
    expect(claims.scope).toBe('HSE')
    // JWT TANPA email/name: email kosong, bukan asumsi.
    expect(claims.email).toBe('')

    const nonHse = await signJwt(keys.privateKey, 'sso-test-1', {
      sub: 'sub-2',
      role: 'viewer',
      scopes: ['HSE'],
    })
    await expect(verifySupabaseJwt(nonHse)).rejects.toBeInstanceOf(SsoAccessDeniedError)
  })

  it('menolak iss salah dan token kedaluwarsa', async () => {
    const now = Math.floor(Date.now() / 1000)
    const wrongIss = new SignJWT({ sub: 'x', role: 'admin', scopes: ['HSE'] })
      .setProtectedHeader({ alg: 'RS256', kid: 'sso-test-1' })
      .setIssuer('https://evil.example')
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
    const bad = await wrongIss.sign(keys.privateKey)
    await expect(verifySupabaseJwt(bad)).rejects.toBeInstanceOf(SsoJwtError)

    const expired = await signJwt(keys.privateKey, 'sso-test-1', {
      sub: 'x',
      role: 'admin',
      scopes: ['HSE'],
      exp: now - 3600,
    })
    await expect(verifySupabaseJwt(expired)).rejects.toBeInstanceOf(SsoJwtError)
  })

  it('refetch JWKS saat kid tak dikenal (rotasi)', async () => {
    const rotated = await makeKeys('sso-test-2')
    const token = await signJwt(rotated.privateKey, 'sso-test-2', {
      sub: 'sub-9',
      role: 'admin',
      scopes: 'HSE',
    })
    let calls = 0
    fetchMock.mockImplementation(async () => {
      calls += 1
      return {
        ok: true,
        json: async () => ({ keys: calls === 1 ? [keys.jwk] : [rotated.jwk] }),
      } as Response
    })
    const claims = await verifySupabaseJwt(token)
    expect(claims.sub).toBe('sub-9')
    expect(calls).toBe(2)
  })

  it('memvalidasi aud hanya bila SSO_AUDIENCE diisi (GAP B2)', async () => {
    const withAud = new SignJWT({ sub: 'a', role: 'admin', scopes: ['HSE'] })
      .setProtectedHeader({ alg: 'RS256', kid: 'sso-test-1' })
      .setIssuer(ISS)
      .setAudience('my-app')
      .setIssuedAt(Math.floor(Date.now() / 1000))
      .setExpirationTime(Math.floor(Date.now() / 1000) + 900)
    const token = await withAud.sign(keys.privateKey)
    // aud diabaikan bila env kosong.
    await expect(verifySupabaseJwt(token)).resolves.toMatchObject({ sub: 'a' })
    vi.stubEnv('SSO_AUDIENCE', 'other-app')
    await expect(verifySupabaseJwt(token)).rejects.toBeInstanceOf(SsoJwtError)
    vi.stubEnv('SSO_AUDIENCE', 'my-app')
    await expect(verifySupabaseJwt(token)).resolves.toMatchObject({ sub: 'a' })
  })
})

describe('sesi aplikasi HMAC (~12 jam)', () => {
  beforeEach(() => {
    vi.stubEnv('HSE_APP_SECRET', 'test-secret-untuk-unit-sesi-hse-1234567890')
    vi.stubEnv('APP_URL', 'https://smk3.nathara.ac.id')
  })
  afterEach(() => vi.unstubAllEnvs())

  const session = {
    userId: 'u-1',
    supabaseSub: 'sub-1',
    email: 'a@example.invalid',
    name: 'A',
    role: 'admin',
    scope: 'HSE',
  }

  it('round-trip sign/verify + menolak token rusak/rahasia beda', async () => {
    const setCookie = createSsoSessionCookie(session)
    expect(setCookie).toContain('Max-Age=43200')
    expect(setCookie).toContain('Secure')
    const value = setCookie.split(';')[0]!.split('=')[1]!
    const got = await getSsoSession(new Headers({ cookie: `${SSO_SESSION_COOKIE}=${value}` }))
    expect(got).toMatchObject({ userId: 'u-1', supabaseSub: 'sub-1', sessionToken: null })
    // Tamper 1 char → null.
    const tampered = `${value.slice(0, 10)}${value[10] === 'A' ? 'B' : 'A'}${value.slice(11)}`
    await expect(
      getSsoSession(new Headers({ cookie: `${SSO_SESSION_COOKIE}=${tampered}` })),
    ).resolves.toBeNull()
    // Rahasia beda → null.
    vi.stubEnv('HSE_APP_SECRET', 'rahasia-lain-yang-juga-cukup-panjang-12345')
    await expect(
      getSsoSession(new Headers({ cookie: `${SSO_SESSION_COOKIE}=${value}` })),
    ).resolves.toBeNull()
  })

  it('null tanpa cookie', async () => {
    await expect(getSsoSession(new Headers())).resolves.toBeNull()
  })
})

describe('flow cookies (state/verifier/link)', () => {
  beforeEach(() => {
    vi.stubEnv('HSE_APP_SECRET', 'test-secret-untuk-unit-sesi-hse-1234567890')
    vi.stubEnv('APP_URL', 'https://smk3.nathara.ac.id')
  })
  afterEach(() => vi.unstubAllEnvs())

  it('round-trip state+verifier terikat dan link cookie kedaluwarsa', async () => {
    const cookies = createSsoFlowCookies({ state: 's', nonce: 'n', verifier: 'v', next: '/x' })
    const jar = new Map<string, string>()
    for (const c of cookies) {
      const [name, rest] = c.split('=', 2)
      jar.set(name!, rest!.split(';')[0]!)
    }
    const header = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
    const flow = readSsoFlowCookies(new Headers({ cookie: header }))
    expect(flow).toMatchObject({ state: 's', nonce: 'n', verifier: 'v', next: '/x' })

    const link = createSsoLinkCookie({ sub: 'sub-1', role: 'admin', scope: 'HSE' })
    const linkValue = link.split(';')[0]!.split('=')[1]!
    const pending = readSsoLinkCookie(new Headers({ cookie: `hse-sso-link=${linkValue}` }))
    expect(pending).toMatchObject({ sub: 'sub-1', role: 'admin', scope: 'HSE' })
  })
})

describe('decideProvision (murni, tanpa DB)', () => {
  const base = { sub: 'sub-1', email: 'a@example.invalid', role: 'admin', scope: 'HSE' }
  it('memakai baris sub, menautkan email bebas, membuat baru admin/HSE', () => {
    expect(decideProvision({ ...base, bySub: { id: 'u1' }, byEmail: null })).toEqual({
      action: 'use',
      userId: 'u1',
    })
    expect(
      decideProvision({ ...base, bySub: null, byEmail: { id: 'u2', supabaseSub: null } }),
    ).toEqual({ action: 'link', userId: 'u2' })
    expect(decideProvision({ ...base, bySub: null, byEmail: null })).toEqual({ action: 'create' })
  })
  it('menolak non-HSE, email terikat sub lain, dan tanpa email (OTP-linking)', () => {
    expect(
      decideProvision({ ...base, role: 'viewer', bySub: null, byEmail: null }).action,
    ).toBe('deny')
    expect(
      decideProvision({
        ...base,
        bySub: null,
        byEmail: { id: 'u3', supabaseSub: 'sub-lain' },
      }).action,
    ).toBe('deny')
    const noEmail = decideProvision({ ...base, email: '', bySub: null, byEmail: null })
    expect(noEmail.action).toBe('deny')
  })
})

describe('authorize URL + code exchange (mock)', () => {
  let keys: KeyMaterial

  beforeEach(async () => {
    vi.stubEnv('APP_URL', 'https://smk3.nathara.ac.id')
    vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key')
    vi.stubEnv('SSO_AUDIENCE', '')
    vi.stubEnv('HSE_APP_SECRET', 'test-secret-untuk-unit-sesi-hse-1234567890')
    __testResetJwksCache()
    keys = await makeKeys('sso-test-1')
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: unknown) => {
        const u = String(url)
        if (u === JWKS_URL) return { ok: true, json: async () => ({ keys: [keys.jwk] }) } as Response
        if (u.endsWith('/.well-known/openid-configuration')) {
          return {
            ok: true,
            json: async () => ({ authorization_endpoint: 'https://sso.nathara.ac.id/authorize' }),
          } as Response
        }
        if (u.includes('/auth/v1/token?grant_type=pkce')) {
          const access = await signJwt(keys.privateKey, 'sso-test-1', {
            sub: 'sub-7',
            role: 'admin',
            scopes: ['HSE'],
          })
          return {
            ok: true,
            json: async () => ({
              access_token: access,
              refresh_token: 'r',
              expires_in: 900,
              user: { id: 'sub-7', email: 'granted@example.org' },
            }),
          } as Response
        }
        if (u.endsWith('/auth/v1/otp')) return { ok: true, json: async () => ({}) } as Response
        if (u.endsWith('/auth/v1/verify')) {
          return {
            ok: true,
            json: async () => ({ user: { id: 'sub-7', email: 'granted@example.org' } }),
          } as Response
        }
        throw new Error(`unexpected fetch ${u}`)
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
  })

  it('membangun authorize URL portal exact (client smk3 + callback exact)', async () => {
    const url = await buildSsoAuthorizeUrl({ state: 'st', nonce: 'no', codeChallenge: 'ch' })
    expect(url.startsWith('https://sso.nathara.ac.id/authorize?')).toBe(true)
    expect(url).toContain('client_id=smk3')
    expect(url).toContain(
      `redirect_uri=${encodeURIComponent('https://smk3.nathara.ac.id/api/auth/sso/callback')}`,
    )
    expect(url).toContain('code_challenge=ch')
    expect(url).toContain('code_challenge_method=S256')
  })

  it('PKCE round-trip mock: code → JWT valid + email exchange', async () => {
    const result = await exchangeAuthCode({ code: 'code-1', codeVerifier: 'ver-1' })
    expect(result.user).toEqual({ id: 'sub-7', email: 'granted@example.org' })
    expect(result.accessToken).toBe(result.idToken)
  })

  it('OTP request + verify mock mengembalikan sub terikat', async () => {
    await expect(requestEmailOtp('granted@example.org')).resolves.toBeUndefined()
    await expect(requestEmailOtp('bukan-email')).rejects.toMatchObject({ name: 'SsoOtpError' })
    const verified = await verifyEmailOtp({ email: 'granted@example.org', code: '123456' })
    expect(verified).toEqual({ sub: 'sub-7', email: 'granted@example.org' })
  })

  it('anon key hilang → fail-closed terkonfigurasi', async () => {
    vi.stubEnv('SUPABASE_ANON_KEY', '')
    await expect(exchangeAuthCode({ code: 'c', codeVerifier: 'v' })).rejects.toBeInstanceOf(
      SsoNotConfiguredError,
    )
    await expect(requestEmailOtp('a@b.c')).rejects.toBeInstanceOf(SsoNotConfiguredError)
  })
})

describe('rate limit SSO', () => {
  beforeEach(() => __testResetRateLimit())
  it('membatasi percobaan berlebih', () => {
    for (let i = 0; i < 10; i++) expect(checkSsoRateLimit('k').ok).toBe(true)
    const blocked = checkSsoRateLimit('k')
    expect(blocked.ok).toBe(false)
    expect(blocked.retryAfterS).toBeGreaterThan(0)
  })
})

describe('audit SSO best-effort', () => {
  it('tidak melempar bila DB tidak terjangkau', async () => {
    await expect(
      auditSsoEvent({ event: 'sso.login.denied', sub: 'x', reason: 'test' }),
    ).resolves.toBeUndefined()
  })
})
