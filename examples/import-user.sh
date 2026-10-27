#!/usr/bin/env bash
# Imports a user with an existing bcrypt hash through the Keycloak Admin REST API.
#
# Usage:
#   KEYCLOAK_URL=http://localhost:8080 REALM=appointiko \
#   ADMIN_USER=admin ADMIN_PASSWORD=... ./examples/import-user.sh [user.json]
#
# Requires: curl, jq. The realm must already exist.
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-appointiko}"
ADMIN_USER="${ADMIN_USER:?set ADMIN_USER}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?set ADMIN_PASSWORD}"
USER_JSON="${1:-$(dirname "$0")/create-user.json}"

token=$(curl -fsS -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=admin-cli" \
  --data-urlencode "username=$ADMIN_USER" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)

status=$(curl -sS -o /dev/stderr -w '%{http_code}' -X POST "$KEYCLOAK_URL/admin/realms/$REALM/users" \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  --data-binary "@$USER_JSON")

if [[ "$status" == "201" ]]; then
  echo "User created."
else
  echo "Keycloak answered HTTP $status" >&2
  exit 1
fi
