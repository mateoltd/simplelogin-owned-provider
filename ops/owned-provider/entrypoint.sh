#!/usr/bin/env sh
set -eu

read_secret() {
  variable="$1"
  file_variable="${variable}_FILE"
  eval "secret_file=\${$file_variable:-}"
  if [ -z "$secret_file" ] || [ ! -r "$secret_file" ]; then
    echo "missing readable secret file for $variable" >&2
    exit 1
  fi
  secret_value="$(tr -d '\r\n' < "$secret_file")"
  if [ -z "$secret_value" ]; then
    echo "empty secret file for $variable" >&2
    exit 1
  fi
  export "$variable=$secret_value"
  unset "$file_variable"
}

for secret_name in \
  FLASK_SECRET \
  PARTNER_API_TOKEN_SECRET \
  RECOVERY_CODE_HMAC_SECRET \
  ALIAS_TRANSFER_TOKEN_SECRET \
  VERP_EMAIL_SECRET \
  MASTER_ENC_KEY_HEX \
  MAC_KEY_HEX \
  ABUSER_HKDF_SALT
do
  read_secret "$secret_name"
done

if [ -n "${MAIL_EDGE_HMAC_KEYS_FILE:-}" ]; then
  read_secret MAIL_EDGE_HMAC_KEYS
fi

read_secret DB_PASSWORD
export DB_URI="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
unset DB_PASSWORD

exec "$@"
