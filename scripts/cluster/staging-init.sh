#!/bin/sh
# HSE STAGING init (PM-HSE-0001 Fase 4) — dijalankan postgres entrypoint HANYA
# saat volume hse-postgres-data masih kosong. Membaca password dari environment
# container (diisi compose dari .env.staging yang chmod 600, TIDAK dari default
# dev). JANGAN pakai scripts/cluster/local-init.sh di staging (password dev).
set -eu

: "${POSTGRES_USER:?POSTGRES_USER wajib}"
: "${HSE_DB_APP_PASSWORD:?HSE_DB_APP_PASSWORD wajib}"
: "${HSE_DB_SUPER_PASSWORD:?HSE_DB_SUPER_PASSWORD wajib}"
: "${HSE_DB_MIGRATOR_PASSWORD:?HSE_DB_MIGRATOR_PASSWORD wajib}"
: "${HSE_DB_BACKUP_PASSWORD:?HSE_DB_BACKUP_PASSWORD wajib}"

psql --username "$POSTGRES_USER" --dbname postgres \
  -v app_password="$HSE_DB_APP_PASSWORD" \
  -v super_password="$HSE_DB_SUPER_PASSWORD" \
  -v migrator_password="$HSE_DB_MIGRATOR_PASSWORD" \
  -v backup_password="$HSE_DB_BACKUP_PASSWORD" \
  -f /opt/hse/provision.sql
