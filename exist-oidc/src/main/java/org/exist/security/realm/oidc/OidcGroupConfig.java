package org.exist.security.realm.oidc;

import org.exist.config.Configurable;
import org.exist.config.Configuration;
import org.exist.config.Configurator;
import org.exist.config.annotation.ConfigurationClass;
import org.exist.config.annotation.ConfigurationFieldAsAttribute;
import org.exist.security.SecurityManager;

/**
 * OidcGroupConfig maps external groups from OIDC to the local groups in the exist realm.
 */
@ConfigurationClass("group")
public class OidcGroupConfig implements Configurable {

    @ConfigurationFieldAsAttribute("external")
    private String external;

    @ConfigurationFieldAsAttribute("local")
    private String local;

    private Configuration configuration;

    public OidcGroupConfig(final Configuration configuration) {
        this.configuration = Configurator.configure(this, configuration);
        if (this.external == null || this.external.trim().isEmpty()) {
            throw new IllegalArgumentException("External OIDC group must not be empty");
        }
        if (this.local == null || this.local.trim().isEmpty()) {
            throw new IllegalArgumentException("Local OIDC group must not be empty");
        }
        this.external = this.external.trim();
        this.local = this.local.trim();
        if (SecurityManager.DBA_GROUP.equalsIgnoreCase(this.local)) {
            throw new IllegalArgumentException("OIDC groups must not map to the DBA group");
        }
    }

    public String getExternal() {
        return external;
    }

    public String getLocal() {
        return local;
    }

    @Override
    public boolean isConfigured() {
        return configuration != null;
    }

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }
}
