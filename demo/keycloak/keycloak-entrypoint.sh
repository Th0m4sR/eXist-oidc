#!/usr/bin/env bash

set -euo pipefail

KC_HOME="/opt/keycloak"
KCADM="${KC_HOME}/bin/kcadm.sh"

REALM="oidc-demo"
ADMIN_USER="${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${KC_BOOTSTRAP_ADMIN_PASSWORD:-password}"

# Start Keycloak first.
"${KC_HOME}/bin/kc.sh" "$@" --import-realm &
KC_PID=$!

trap 'kill -TERM "${KC_PID}" 2>/dev/null || true' TERM INT

echo "Waiting for Keycloak..."

until "${KCADM}" config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user "${ADMIN_USER}" \
    --password "${ADMIN_PASSWORD}" >/dev/null 2>&1; do

    if ! kill -0 "${KC_PID}" 2>/dev/null; then
        echo "Keycloak stopped before becoming ready."
        wait "${KC_PID}"
        exit 1
    fi

    sleep 2
done

echo "Keycloak is ready."

until "${KCADM}" config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user "${KC_BOOTSTRAP_ADMIN_USERNAME}" \
    --password "${KC_BOOTSTRAP_ADMIN_PASSWORD}" >/dev/null 2>&1
do
    sleep 2
done

create_user() {
    USERNAME="$1"
    FIRST_NAME="$2"
    LAST_NAME="$3"
    EMAIL="$4"

    "${KCADM}" create users \
        -r "${REALM}" \
        -s "username=${USERNAME}" \
        -s "firstName=${FIRST_NAME}" \
        -s "lastName=${LAST_NAME}" \
        -s "email=${EMAIL}" \
        -s enabled=true \
        -s emailVerified=true >/dev/null 2>&1 || true

    "${KCADM}" set-password \
        -r "${REALM}" \
        --username "${USERNAME}" \
        --new-password password
}

create_user \
    "oidc-demo" \
    "OIDC" \
    "Demo" \
    "oidc-demo@example.com"

create_user \
    "oidc-wrong-group" \
    "Wrong" \
    "Group" \
    "oidc-wrong-group@example.com"

USER_ID="$(
    "${KCADM}" get users \
        -r "${REALM}" \
        -q username=oidc-demo \
        --fields id \
        --format csv \
        --noquotes
)"

GROUP_ID="$(
    "${KCADM}" get groups \
        -r "${REALM}" \
        -q search=KeycloakTEI \
        -q exact=true \
        --fields id \
        --format csv \
        --noquotes
)"

if [ -z "${USER_ID}" ]; then
    echo "User oidc-demo was not found."
    exit 1
fi

if [ -z "${GROUP_ID}" ]; then
    echo "Group KeycloakTEI was not found."
    exit 1
fi

"${KCADM}" update \
    "users/${USER_ID}/groups/${GROUP_ID}" \
    -r "${REALM}" \
    -s "userId=${USER_ID}" \
    -s "groupId=${GROUP_ID}" \
    -n

echo "Added oidc-demo to /KeycloakTEI"

wait "${KC_PID}"