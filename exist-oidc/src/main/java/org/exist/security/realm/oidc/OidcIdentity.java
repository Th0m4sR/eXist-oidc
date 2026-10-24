package org.exist.security.realm.oidc;

import java.util.Set;

import org.pac4j.oidc.profile.OidcProfile;

/**
 * OidcIdentity structures the claims returned by the OIDC server that are used to manage users
 */
public final class OidcIdentity {

    private final String issuer;
    private final String subject;
    private final String username;
    private final Set<String> groups;

    private OidcIdentity(
            String issuer,
            String subject,
            String username,
            Set<String> groups) {

        this.issuer = issuer;
        this.subject = subject;
        this.username = username;
        this.groups = groups;
    }

    public OidcIdentity(OidcProfile oidcProfile) {
        this(
            oidcProfile.getIssuer(),
            oidcProfile.getSubject(),
            oidcProfile.getUsername(),
            oidcProfile.getRoles()
        );
    }

    public String issuer() {
        return issuer;
    }

    public String subject() {
        return subject;
    }

    public String username() {
        return username;
    }

    public Set<String> groups() {
        return groups;
    }
}