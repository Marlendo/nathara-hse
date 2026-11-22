-- PM-HSE-0001 (SA-HSE § Drizzle): SSO Nathara — tambah kolom pemetaan identitas
-- IdP di tabel "user". Aditif: tidak menyentuh kolom/baris yang sudah ada.
-- `supabase_sub` unik: satu identitas IdP = satu akun. Nullable agar baris
-- pra-SSO tetap valid; provisioning login pertama mengisinya (sekali saja).
ALTER TABLE "user" ADD COLUMN "supabase_sub" text;--> statement-breakpoint
CREATE UNIQUE INDEX "user_supabase_sub_ux" ON "user" USING btree ("supabase_sub");--> statement-breakpoint
