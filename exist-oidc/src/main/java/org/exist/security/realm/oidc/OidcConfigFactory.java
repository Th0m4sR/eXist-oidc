package org.exist.security.realm.oidc;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.util.ConfigurationHelper;
import org.pac4j.core.authorization.authorizer.Authorizer;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.config.ConfigFactory;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.http.callback.NoParameterCallbackUrlResolver;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.http.client.direct.DirectBasicAuthClient;
import org.exist.EXistException;
import org.exist.security.AuthenticationException;
import org.exist.security.Subject;
import org.exist.security.internal.RealmImpl;
import org.exist.storage.BrokerPool;

import java.nio.file.Files;
import java.nio.file.Path;

public class OidcConfigFactory implements ConfigFactory{

    public static Config OIDC_CONFIG_INSTANCE;

    private static final Logger LOG = LogManager.getLogger(OidcConfigFactory.class);
    private static final String PROPERTIES_FILE = "oidc.properties";

    private final Properties fileProps = loadProperties();
    // private final ServletContext ctx;

    @Override
    public Config build(final Object... parameters) {

        LOG.info("READING OIDC PROPERTIES");
        String clientId            = required("oidc.clientId");
        String secret              = optional("oidc.secret", null);
        String scope               = optional("oidc.scope", "openid profile email");
        String discoveryUri        = required("oidc.discoveryUri");
        String callbackUrl         = required("oidc.callbackUrl");
        List<String> allowedOidcGroups = requiredList("oidc.allowedGroups");
        List<String> allowedLocalGroups = requiredList("local.allowedGroups");
        LOG.info("SUCCESSFULlY READ OIDC PROPERTIES");

        final OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setClientId(clientId);
        if (secret != null && !secret.isEmpty()) {
            oidcConfiguration.setSecret(secret);
        }
        oidcConfiguration.setScope(scope);
        oidcConfiguration.setUseNonce(true);
        oidcConfiguration.setDiscoveryURI(discoveryUri);

        // OIDC CLIENT
        LOG.debug("SET OIDC CONFIG");
        final OidcClient<OidcConfiguration> oidcClient = new OidcClient<OidcConfiguration>(oidcConfiguration);
        oidcClient.setName("existOidcClient");
        oidcClient.setCallbackUrl(callbackUrl);
        oidcClient.setCallbackUrlResolver(new NoParameterCallbackUrlResolver());
        LOG.debug("Created OIDC client");
        
        // Groups that are allowed to access the protected site
        LOG.debug("Allowed OIDC groups: " + allowedOidcGroups);
        LOG.debug("Allowed local groups: " + allowedLocalGroups);
        // Only allowed roles should be able to access the page https://www.pac4j.org/docs/authorizers.html
        oidcClient.setAuthorizationGenerator((ctx, profile) -> {
            Object profileGroups = profile.getAttribute("groups");
            if (profileGroups instanceof Collection<?>) {
                Collection<?> groups = (Collection<?>) profileGroups;

                groups.stream().filter(group -> group != null).map(String::valueOf).forEach(profile::addRole);

            } else if (profileGroups != null && profileGroups.getClass().isArray()) {
                int length = Array.getLength(profileGroups);

                for (int i = 0; i < length; i++) {
                    Object group = Array.get(profileGroups, i);
                    if (group != null) {
                        profile.addRole(String.valueOf(group));
                    }
                }
            }
            return Optional.of(profile);
        });

        // TODO WHAT MUST HAPPEN HERE???
        // BASIC AUTH CLIENT
        final BrokerPool pool;
        try {
            pool = BrokerPool.getInstance();
        } catch (final EXistException e) {
            throw new IllegalStateException("Could not obtain the running eXist-db BrokerPool", e);
        }
        final Authenticator<UsernamePasswordCredentials> basicAuthenticator = new Authenticator<UsernamePasswordCredentials>() {
            @Override
            public void validate(final UsernamePasswordCredentials credentials, final WebContext context) {
                final Subject subject;
                try {
                    subject = pool.getSecurityManager().authenticate(credentials.getUsername(), credentials.getPassword());
                } catch (final AuthenticationException e) {
                    throw new CredentialsException("Invalid username or password", e);
                }
                final CommonProfile profile = new CommonProfile();
                profile.setId(subject.getName());
                profile.addAttribute(Pac4jConstants.USERNAME, subject.getName());
                for (final String group : subject.getGroups()) {
                    profile.addRole(group);
                }
                credentials.setUserProfile(profile);
                // If supported by your WebContext implementation:
                context.setRequestAttribute("exist.authenticated.subject", subject);
            }
        };
        final DirectBasicAuthClient basicAuthClient = new DirectBasicAuthClient(basicAuthenticator);
        basicAuthClient.setName("existBasicClient");
        basicAuthClient.setRealmName(RealmImpl.ID);
        LOG.debug("Created Basic Auth client");

        // Create config
        final Clients clients = new Clients(callbackUrl, oidcClient, basicAuthClient);
        final Config config = new Config(clients);
        final Authorizer<CommonProfile> authorizer = (context, profiles) -> {
            if (profiles == null || profiles.isEmpty()) {
                return false;
            }
            for (final CommonProfile profile : profiles) {
                // Basic authentication must have an allowed role.
                if (profile.getClientName().equalsIgnoreCase("existBasicClient") && profile.getRoles().stream().anyMatch(allowedLocalGroups::contains)) {
                    return true;
                }
                // OIDC authentication must have an allowed role.
                // RequireAnyRoleAuthorizer instead?
                if (profile instanceof OidcProfile && profile.getRoles().stream().anyMatch(allowedOidcGroups::contains)) {
                    return true;
                }
            }
            return false;
        };
        config.addAuthorizer("roleAuthorizer", authorizer);
        
        LOG.info("FINISHED CONFIG BUILD");

        OIDC_CONFIG_INSTANCE = config;
        
        return config;
    }

    private static Properties loadProperties() {
        Properties props = new Properties();

        Optional<Path> home = ConfigurationHelper.getExistHome();
        if (!home.isPresent()) {
            LOG.warn("exist.home not found, skipping {}", PROPERTIES_FILE);
            return props;
        }

        Path file = home.get().resolve("etc").resolve(PROPERTIES_FILE);
        if (!Files.isReadable(file)) {
            LOG.info("No readable {} found, using other sources", file);
            return props;
        }

        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            props.load(reader);
            LOG.info("Loaded OIDC settings from {}", file);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read " + file, e);
        }
        return props;
    }

    /**
     * Lookup order:
     * environment variable -> system property -> oidc.properties -> web.xml context-param -> default
     */
    private String optional(String key, String def) {
        String v = System.getenv(key.toUpperCase().replace('.', '_'));
        if (v == null) v = System.getProperty(key);
        if (v == null) v = fileProps.getProperty(key);
        if (v != null) v = v.trim();
        return (v != null && !v.isEmpty()) ? v : def;
    }

    private String required(String key) {
        String v = optional(key, null);
        if (v == null) {
            throw new IllegalStateException("Missing OIDC setting: " + key);
        }
        return v;
    }

    private List<String> requiredList(final String key) {
        final String value = required(key);
        if (value == null || value.trim().isEmpty()) {
            return Collections.emptyList();
        }
        final List<String> values = new ArrayList<>();
        for (final String item : value.split(",")) {
            if (item == null) {
                continue;
            }
            final String trimmedItem = item.trim();
            if (!trimmedItem.isEmpty() && !values.contains(trimmedItem)) {
                values.add(trimmedItem);
            }
        }
        return values;
    }
}
