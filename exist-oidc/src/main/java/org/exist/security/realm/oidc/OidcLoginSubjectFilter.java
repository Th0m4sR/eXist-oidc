package org.exist.security.realm.oidc;

import java.io.IOException;
import java.security.Principal;
import java.util.Optional;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.EXistException;
import org.exist.security.AuthenticationException;
import org.exist.security.Subject;
import org.exist.storage.BrokerPool;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.session.JEESessionStore;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.oidc.profile.OidcProfile;

public class OidcLoginSubjectFilter implements Filter {
    private static final Logger LOG = LogManager.getLogger(OidcLoginSubjectFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOG.info("Initialized Login Filter.");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        final HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        final Principal principal = httpServletRequest.getUserPrincipal();

        if (principal == null) {
            chain.doFilter(request, response);
            return;
        }
        LOG.info("Principal: {}", principal.getName());

        final JEEContext context = new JEEContext(httpServletRequest, httpServletResponse);
        /*
         * JEESessionStore reads the same HttpSession into which
         * CallbackFilter stored the pac4j profile.
         */
        final JEESessionStore sessionStore = new JEESessionStore();
        final ProfileManager<UserProfile> profileManager = new ProfileManager<>(context);
        profileManager.setSessionStore(sessionStore);

        final Optional<UserProfile> profileOptional = profileManager.get(true);

        if (!profileOptional.isPresent()) {
            LOG.warn("No pac4j profile found for principal {}", principal.getName());
            chain.doFilter(request, response);
            return;
        }

        final UserProfile profile = profileOptional.get();

        if (!(profile instanceof OidcProfile)) {
            LOG.warn("Expected OidcProfile but found {}", profile.getClass().getName());
                chain.doFilter(request, response);
            return;
        }

        final OidcProfile oidcProfile = (OidcProfile) profile;

        try {
            LOG.info(
                "OIDC profile: id='{}', username='{}', issuer='{}', " +
                "subject='{}', hasIdToken={}, hasAccessToken={}, attributes={}",
                oidcProfile.getId(),
                oidcProfile.getUsername(),
                oidcProfile.getIssuer(),
                oidcProfile.getSubject(),
                oidcProfile.getIdToken() != null,
                oidcProfile.getAccessToken() != null,
                oidcProfile.getAttributes().keySet()
            );
            LOG.info(oidcProfile.toString());

            final Subject subject = BrokerPool.getInstance().getSecurityManager().authenticate(oidcProfile.getUsername(), new OidcIdentity(oidcProfile));

            LOG.info("Authenticated eXist subject: {}", subject.toString());

            final HttpServletRequestWrapper authenticatedRequest = new HttpServletRequestWrapper(httpServletRequest) {

                @Override
                public Principal getUserPrincipal() {
                    return subject;
                }

                @Override
                public String getRemoteUser() {
                    return subject.getName();
                }
            };
            chain.doFilter(authenticatedRequest, response);
        } catch (EXistException e) {
            LOG.error("An error occurred while creating the subject", e);
            httpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        } catch (AuthenticationException e) {
            LOG.error("OIDC authentication failed", e);
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Override
    public void destroy() {
        // Do nothing for now
    }
    
}
