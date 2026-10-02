#!/usr/bin/env bash
# Regenerates the vault fixtures with the real `ansible-vault`.
# The password is a throwaway test value, never a real secret.
set -euo pipefail
cd "$(dirname "$0")"
PW=password.txt
printf 'test-password-123\n' > "$PW"
av() { ansible-vault "$@" --vault-password-file "$PW"; }

printf 'hello' | av encrypt --output - > hello.vault
printf 'api_token: abc123\nport: 8080\n' | av encrypt --output - > file.vault
printf 'pässwörd €🔑' | av encrypt --output - > utf8.vault
printf 'hello' | ansible-vault encrypt --vault-id "dev@$PW" --encrypt-vault-id dev --output - > dev_id.vault
{
  echo '---'
  echo 'plain_key: hello world'
  av encrypt_string 'super-secret' --name db_password 2>/dev/null
  echo
  echo 'other_key: value'
} > inline.yml
