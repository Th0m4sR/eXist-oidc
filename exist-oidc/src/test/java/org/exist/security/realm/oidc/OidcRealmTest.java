package org.exist.security.realm.oidc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import org.exist.config.Configuration;
import org.exist.security.AbstractAccount;
import org.exist.security.Account;
import org.exist.security.AuthenticationException;
import org.exist.security.Group;
import org.exist.security.PermissionDeniedException;
import org.exist.security.SecurityManager;
import org.exist.security.Subject;
import org.exist.security.internal.SecurityManagerImpl;
import org.exist.storage.BrokerPool;
import org.exist.storage.DBBroker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pac4j.oidc.profile.OidcProfile;

@ExtendWith(MockitoExtension.class)
class OidcRealmTest {

    private static final String ISSUER = "https://issuer.example";

    @Mock
    private SecurityManagerImpl securityManager;

    @Mock
    private Configuration configuration;

    @Mock
    private Account account;

    @Mock
    private Group group;

    @Mock
    private DBBroker broker;

    @Mock
    private BrokerPool brokerPool;

    private OidcRealm realm;

    @BeforeEach
    void setUp() {
        when(configuration.getProperty("issuer")).thenReturn(ISSUER);
        when(configuration.getProperty("audience")).thenReturn("client");
        when(configuration.getProperty("usernameClaim"))
                .thenReturn("preferred_username");
        when(configuration.getProperty("groupsClaim")).thenReturn("groups");
        when(configuration.getProperty("defaultGroupName"))
                .thenReturn("users");
        when(configuration.getProperty("clientId"))
                .thenReturn("exist-client");

        realm = Mockito.spy(
                new OidcRealm(securityManager, configuration)
        );

        realm.oidcGroups = Collections.emptyList();
    }

    private OidcIdentity identity(
            final String username,
            final String subject,
            final String issuer,
            final Set<String> groups) {

        OidcProfile profile = mock(OidcProfile.class);

        when(profile.getIssuer()).thenReturn(issuer);
        when(profile.getSubject()).thenReturn(subject);
        when(profile.getUsername()).thenReturn(username);
        when(profile.getRoles()).thenReturn(groups);

        return new OidcIdentity(profile);
    }

    private OidcIdentity identity(final String username) {
        return identity(
                username,
                "subject",
                ISSUER,
                Collections.emptySet()
        );
    }

    private AbstractAccount oidcAccount(
            final String username,
            final String subject,
            final String issuer,
            final boolean enabled) {

        AbstractAccount result = mock(AbstractAccount.class);

        when(result.getName()).thenReturn(username);
        when(result.getRealmId()).thenReturn(OidcRealm.ID);
        when(result.isEnabled()).thenReturn(enabled);
        when(result.getMetadataValue(OidcSchemaType.SUBJECT))
                .thenReturn(subject);
        when(result.getMetadataValue(OidcSchemaType.ISSUER))
                .thenReturn(issuer);

        return result;
    }

    private void prepareDatabase() throws Exception {
        Subject systemSubject = mock(Subject.class);

        when(securityManager.getSystemSubject())
                .thenReturn(systemSubject);

        when(brokerPool.get(Mockito.<Optional<Subject>>any()))
                .thenReturn(broker);

        doReturn(brokerPool)
                .when(realm)
                .getDatabase();
    }

    @Test
    void constructorRejectsNullDefaultGroup() {
        when(configuration.getProperty("defaultGroupName"))
                .thenReturn(null);

        assertThrows(
                IllegalArgumentException.class,
                () -> new OidcRealm(securityManager, configuration)
        );
    }

    @Test
    void constructorRejectsEmptyDefaultGroup() {
        when(configuration.getProperty("defaultGroupName"))
                .thenReturn(" ");

        assertThrows(
                IllegalArgumentException.class,
                () -> new OidcRealm(securityManager, configuration)
        );
    }

    @Test
    void constructorRejectsDbaGroup() {
        when(configuration.getProperty("defaultGroupName"))
                .thenReturn(SecurityManager.DBA_GROUP);

        assertThrows(
                IllegalArgumentException.class,
                () -> new OidcRealm(securityManager, configuration)
        );
    }

    @Test
    void authenticateRejectsWrongCredentialsObject() {
        AuthenticationException exception = assertThrows(
                AuthenticationException.class,
                () -> realm.authenticate(
                        "user",
                        "not-an-oidc-identity"
                )
        );

        assertNotNull(exception);
    }

    @Test
    void deleteAccountAlwaysDenied() {
        assertThrows(
                PermissionDeniedException.class,
                () -> realm.deleteAccount(account)
        );
    }

    @Test
    void deleteGroupAlwaysDenied() {
        assertThrows(
                PermissionDeniedException.class,
                () -> realm.deleteGroup(group)
        );
    }

    @Test
    void createAccountReturnsExistingOidcAccount() throws Exception {
        prepareDatabase();

        OidcIdentity identity = identity("john");

        doReturn(account)
                .when(realm)
                .getAccount("john");

        when(account.getRealmId())
                .thenReturn(OidcRealm.ID);

        Account result = realm.createAccount(identity);

        assertSame(account, result);

        verify(securityManager, never())
                .addAccount(any());
    }

    @Test
    void createAccountRejectsAccountCollisionAcrossRealms()
            throws Exception {

        prepareDatabase();

        OidcIdentity identity = identity("admin");

        doReturn(account)
                .when(realm)
                .getAccount("admin");

        when(account.getRealmId())
                .thenReturn("exist");

        assertThrows(
                AuthenticationException.class,
                () -> realm.createAccount(identity)
        );

        verify(securityManager, never())
                .addAccount(any());
    }

    @Test
    void createAccountCreatesDefaultGroupIfMissing() throws Exception {
        prepareDatabase();

        OidcIdentity identity = identity(
                "john",
                "subject",
                ISSUER,
                Collections.emptySet()
        );

        doReturn(null)
                .when(realm)
                .getAccount("john");

        doReturn(null)
                .when(realm)
                .getGroup("users");

        when(securityManager.getGroup("users"))
                .thenReturn(null);

        when(securityManager.addGroup(
                any(DBBroker.class),
                any(Group.class)
        )).thenReturn(group);

        AbstractAccount createdAccount =
                mock(AbstractAccount.class);

        when(createdAccount.getRealmId())
                .thenReturn(OidcRealm.ID);

        when(securityManager.addAccount(any()))
                .thenReturn(createdAccount);

        Account result = realm.createAccount(identity);

        assertSame(createdAccount, result);

        verify(securityManager).addGroup(
                eq(broker),
                any(Group.class)
        );

        verify(securityManager).addAccount(any());

        verify(broker).pushSubject(any(Subject.class));
        verify(broker).popSubject();
    }

    @Test
    void authenticateRejectsAccountFromDifferentRealm() {
        OidcIdentity identity = identity(
                "john",
                "sub",
                ISSUER,
                Collections.emptySet()
        );

        doReturn(account)
                .when(realm)
                .getAccount("john");

        when(account.getRealmId())
                .thenReturn("exist");

        assertThrows(
                AuthenticationException.class,
                () -> realm.authenticate("john", identity)
        );
    }

    @Test
    void authenticateRejectsDisabledAccount() {
        OidcIdentity identity = identity(
                "john",
                "sub",
                ISSUER,
                Collections.emptySet()
        );

        AbstractAccount disabledAccount =
                mock(AbstractAccount.class);

        when(disabledAccount.getRealmId())
                .thenReturn(OidcRealm.ID);

        when(disabledAccount.isEnabled())
                .thenReturn(false);

        when(disabledAccount.getName())
                .thenReturn("john");

        doReturn(disabledAccount)
                .when(realm)
                .getAccount("john");

        assertThrows(
                AuthenticationException.class,
                () -> realm.authenticate("john", identity)
        );
    }

    @Test
    void authenticateRejectsMetadataMismatch() {
        OidcIdentity identity = identity(
                "john",
                "expected-subject",
                ISSUER,
                Collections.emptySet()
        );

        AbstractAccount existingAccount = oidcAccount(
                "john",
                "different-subject",
                ISSUER,
                true
        );

        doReturn(existingAccount)
                .when(realm)
                .getAccount("john");

        assertThrows(
                AuthenticationException.class,
                () -> realm.authenticate("john", identity)
        );
    }

    @Test
    void authenticateRejectsWrongIssuer() {
        OidcIdentity identity = identity(
                "john",
                "subject",
                "https://another-issuer",
                Collections.emptySet()
        );

        assertThrows(
                AuthenticationException.class,
                () -> realm.authenticate("john", identity)
        );

        verify(realm, never())
                .getAccount(anyString());
    }

    @Test
    void authenticateCreatesAccountWhenMissing() throws Exception {
        OidcIdentity identity = identity(
                "john",
                "sub",
                ISSUER,
                Collections.emptySet()
        );
        doReturn(null)
                .when(realm)
                .getAccount("john");
        AbstractAccount createdAccount = mock(AbstractAccount.class);
        when(createdAccount.isEnabled())
                .thenReturn(true);
        when(createdAccount.getMetadataValue(OidcSchemaType.SUBJECT))
                .thenReturn("sub");
        when(createdAccount.getMetadataValue(OidcSchemaType.ISSUER))
                .thenReturn(ISSUER);
        doReturn(createdAccount)
                .when(realm)
                .createAccount(identity);
        Subject subject = realm.authenticate("john", identity);
        assertNotNull(subject);
        verify(realm).createAccount(identity);
    }

    @Test
    void getLocalUserGroupsMatchesConfiguredGroups() throws Exception {
        OidcGroupConfig group1 = mock(OidcGroupConfig.class);
        OidcGroupConfig group2 = mock(OidcGroupConfig.class);

        when(group1.getExternal())
                .thenReturn("oidc-users");

        when(group1.getLocal())
                .thenReturn("users");

        when(group2.getExternal())
                .thenReturn("oidc-admins");

        realm.oidcGroups = Arrays.asList(group1, group2);

        Method method = OidcRealm.class.getDeclaredMethod(
                "getLocalUserGroups",
                Set.class
        );

        method.setAccessible(true);

        @SuppressWarnings("unchecked")
        Set<String> result = (Set<String>) method.invoke(
                realm,
                Collections.singleton("oidc-users")
        );

        assertEquals(
                Collections.singleton("users"),
                result
        );

        verify(group1).getExternal();
        verify(group1).getLocal();
        verify(group2).getExternal();
        verify(group2, never()).getLocal();
    }

    @Test
    void requireOidcAccountRejectsForeignRealm() throws Exception {
        when(account.getRealmId())
                .thenReturn("exist");

        Method method = OidcRealm.class.getDeclaredMethod(
                "requireOidcAccount",
                Account.class
        );

        method.setAccessible(true);

        InvocationTargetException exception = assertThrows(
                InvocationTargetException.class,
                () -> method.invoke(realm, account)
        );

        assertInstanceOf(
                AuthenticationException.class,
                exception.getCause()
        );
    }
}