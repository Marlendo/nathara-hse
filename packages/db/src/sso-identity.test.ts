import { getTableConfig } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { account, users } from './schema/core'

// PM-HSE-0001: SSO Nathara — `users.supabase_sub` unik (pemetaan IdP) dan
// `account.password` SUDAH DIHAPUS (jalur password lokal mati total).

describe('sso identity schema (PM-HSE-0001)', () => {
  it('memetakan users.supabase_sub ke kolom supabase_sub + unique index', () => {
    const config = getTableConfig(users)
    const columns = getTableConfig(users).columns
    const names = columns.map((c) => c.name)
    expect(names).toContain('supabase_sub')
    const index = config.indexes.find((i) => i.config.name === 'user_supabase_sub_ux')
    expect(index?.config.unique).toBe(true)
    expect(index?.config.columns.map((c) => ('name' in c ? c.name : null))).toEqual([
      'supabase_sub',
    ])
  })

  it('tidak lagi memiliki kolom account.password', () => {
    const names = getTableConfig(account).columns.map((c) => c.name)
    expect(names).not.toContain('password')
  })
})
