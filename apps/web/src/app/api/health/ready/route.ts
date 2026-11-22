import { NextResponse } from 'next/server'
import { sql } from 'drizzle-orm'
import { db, superDb } from '@beaconhs/db'
import { assertRedisReady } from '@beaconhs/jobs/health'

export const dynamic = 'force-dynamic'

const CACHE_MS = 5_000
let cached: { ready: boolean; expiresAt: number } | undefined
let pending: Promise<boolean> | undefined

async function runChecks() {
  try {
    // Readiness = DB + Redis. Auth readiness (kontrak SSO TODO-SSO-1..5) divalidasi
    // di rute SSO / halaman login, bukan di sini — tidak ada secret sesi lokal lagi.
    await Promise.all([
      db.execute(sql`select 1`),
      superDb.execute(sql`select 1`),
      assertRedisReady(),
    ])
    return true
  } catch {
    return false
  }
}

async function isReady() {
  const now = Date.now()
  if (cached && cached.expiresAt > now) return cached.ready

  pending ??= runChecks().finally(() => {
    pending = undefined
  })
  const ready = await pending
  cached = { ready, expiresAt: Date.now() + CACHE_MS }
  return ready
}

export async function GET() {
  const ready = await isReady()
  return NextResponse.json(
    {
      status: ready ? 'ready' : 'unavailable',
      version: process.env.APP_VERSION ?? 'unknown',
    },
    {
      status: ready ? 200 : 503,
      headers: { 'Cache-Control': 'no-store' },
    },
  )
}
