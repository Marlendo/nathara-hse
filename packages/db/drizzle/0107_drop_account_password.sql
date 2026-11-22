-- PM-HSE-0001 (SA-HSE § Drizzle): jalur password lokal DIMATIKAN TOTAL.
-- DINYATAKAN AMAN: satu-satunya penulis/pembaca `account.password` adalah
-- jalur better-auth yang ikut dimatikan (K-1/K-2/K-14); tidak ada modul HSE
-- yang membaca kolom ini. Hapus baris kredensial legacy dulu, lalu kolomnya.
-- `session`/`verification` KEEP sampai sesi SSO hijau (hindari lock-out total).
DELETE FROM "account" WHERE "providerId" = 'credential';--> statement-breakpoint
ALTER TABLE "account" DROP COLUMN "password";--> statement-breakpoint
