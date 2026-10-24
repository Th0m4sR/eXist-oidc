package org.exist.security.realm.oidc;

import org.exist.security.SchemaType;

public enum OidcSchemaType implements SchemaType {

    ISSUER("https://oidc.schema/schema/oidc/issuer", "OidcIssuer"),
    SUBJECT("https://oidc.schema/schema/oidc/subject", "OidcSubject");

    private final String namespace;
    private final String alias;

    OidcSchemaType(String namespace, String alias) {
        this.namespace = namespace;
        this.alias = alias;
    }

    @Override
    public String getNamespace() {
        return namespace;
    }

    @Override
    public String getAlias() {
        return alias;
    }
}
