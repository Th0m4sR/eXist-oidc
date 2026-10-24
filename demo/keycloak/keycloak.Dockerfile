FROM quay.io/keycloak/keycloak:26.7.0

COPY demo/keycloak/keycloak-entrypoint.sh /etc/keycloak/entrypoint.sh
COPY demo/keycloak/oidc-demo-realm.json /opt/keycloak/data/import/oidc-demo-realm.json

ENTRYPOINT ["/etc/keycloak/entrypoint.sh"]