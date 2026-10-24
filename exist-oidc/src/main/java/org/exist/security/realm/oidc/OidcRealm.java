package org.exist.security.realm.oidc;

import java.security.SecureRandom;
import org.exist.EXistException;
import org.exist.config.ConfigurationException;
import org.exist.config.annotation.ConfigurationClass;
import org.exist.config.annotation.ConfigurationFieldAsAttribute;
import org.exist.config.annotation.ConfigurationFieldAsElement;
import org.exist.config.annotation.ConfigurationFieldClassMask;
import org.exist.security.AbstractAccount;
import org.exist.security.AbstractRealm;
import org.exist.security.Account;
import org.exist.security.AuthenticationException;
import org.exist.security.Group;
import org.exist.security.PermissionDeniedException;
import org.exist.security.Subject;
import org.exist.security.internal.SecurityManagerImpl;
import org.exist.security.internal.SubjectAccreditedImpl;
import org.exist.security.internal.aider.GroupAider;
import org.exist.security.internal.aider.UserAider;
import org.exist.security.SecurityManager;
import org.exist.storage.DBBroker;
import org.exist.config.Configuration;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.exist.security.internal.RealmImpl;

// Debugging
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * OidcRealm authenticates users using access tokens from oidc servers.
 * The current implementation allows only Keycloak
 */
@ConfigurationClass("realm")
public class OidcRealm extends AbstractRealm {

    private static final Logger LOG = LogManager.getLogger(OidcRealm.class);
    
    // matches the /db/system/security/exist collection
    private static final String INTERNAL_REALM_ID = RealmImpl.ID;

    @ConfigurationFieldAsAttribute("id")
    public static String ID = "Oidc";

    @ConfigurationFieldAsAttribute("version")
    public static final String version = "1.0";

    /**
     * Group name for users without matching group from the group config
     */
    @ConfigurationFieldAsAttribute("defaultGroupName")
    public String defaultGroupName;

    /**
     * Group names for users matching groups between the OIDC server and eXist-db
     */
    @ConfigurationFieldAsElement("group")
    @ConfigurationFieldClassMask("org.exist.security.realm.oidc.OidcGroupConfig")
    public List<OidcGroupConfig> oidcGroups;

    /**
     * URL to the token issuer
     */
    @ConfigurationFieldAsAttribute("issuer")
    public String issuer;

    /**
     * Claim that contains the audience returned by the token issuer
     */
    @ConfigurationFieldAsAttribute("audience")
    public String audience;

    /**
     * Claim that contains the username returned by the token issuer
     */
    @ConfigurationFieldAsAttribute("usernameClaim")
    public String usernameClaim;

    /**
     * Claim that contains the groups returned by the token issuer
     */
    @ConfigurationFieldAsAttribute("groupsClaim")
    public String groupsClaim;

    @ConfigurationFieldAsAttribute("clientId")
    public String clientId;

    public OidcRealm(final SecurityManagerImpl sm, final Configuration config) {
        super(sm, config);
        this.issuer = config.getProperty("issuer");
        this.audience = config.getProperty("audience");
        this.usernameClaim = config.getProperty("usernameClaim");
        this.groupsClaim = config.getProperty("groupsClaim");
        this.defaultGroupName = config.getProperty("defaultGroupName");
        this.clientId = config.getProperty("clientId");

        if (SecurityManager.DBA_GROUP.equalsIgnoreCase(defaultGroupName)) {
            throw new IllegalArgumentException("OIDC default group must not be the DBA group");
        }

        if (this.defaultGroupName == null || this.defaultGroupName.trim().isEmpty()) {
            throw new IllegalArgumentException("Default group name must not be empty or null.");
        }
        if (this.defaultGroupName.length() > 128) {
            throw new IllegalArgumentException("Default group name is too long.");
        }
        LOG.info("OIDC REALM CREATED");
    }

    @Override
    public String getId() {
        return ID;
    }

    private Subject establishSubject(OidcIdentity identity) throws AuthenticationException {
        if (identity == null) {
            LOG.error("identity must not be null");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "No identity was provided for this subject");
        }
        if(identity.issuer() == null) {
            LOG.error("issuer must not be null");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "No issuer was provided for this subject");
        }
        if (!identity.issuer().equals(this.issuer)) {
            LOG.error("issuer must equal the configured issuer");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Invalid token issuer");
        }
        if (identity.subject() == null) {
            LOG.error("subject must not be null");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Subject must not be null");
        }
        if (identity.subject().trim().isEmpty()) {
            LOG.error("subject must not be empty");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Subject must not be empty");
        }
        if (identity.groups() == null) {
            LOG.error("groups must not be null");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Groups must not be null");
        }
        String accountName = identity.username();
        LOG.info("OIDC authentication started for account '{}'", accountName);
        // Simply checking if values were submitted
        if (accountName == null) {
            LOG.warn("Account was not found '{}'", accountName);
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "No accountname was provided.");
        }
        if (accountName.trim().isEmpty()) {
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Account name must not be empty");
        }

        LOG.info("Trying to find matching account.");

        // Get the account
        Account account = getAccount(accountName);
        // Make sure the account exists only in the OIDC realm.
        //  Otherwise, an OIDC user "admin" might get authenticated as dba
        if (account != null && !getId().equals(account.getRealmId())) {
            LOG.error("OIDC username '{}' collides with account in realm '{}'", accountName, account.getRealmId());
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Invalid account name");
        }
        // Create the account if no account was found
        if (account == null) {
            LOG.warn("No matching account found. Will create one.");
            account = createAccount(identity);
            LOG.warn("Successfully created account.");
        }
        // Throw exception if account was neither found nor created
        if(!(account instanceof AbstractAccount)){
            LOG.warn("Account was not found and creation failed.");
            throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "account is not an AbstractAccount");
        }
        // Make sure the account is enabled
        if (!account.isEnabled()) {
            LOG.warn("OIDC account '{}' is disabled", account.getName());
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Invalid account");
        }
        // Make sure subject and issuer match the found account
        String storedSubject = account.getMetadataValue(OidcSchemaType.SUBJECT);
        String storedIssuer = account.getMetadataValue(OidcSchemaType.ISSUER);
        if (!storedSubject.equals(identity.subject()) || !storedIssuer.equals(identity.issuer())) {
            LOG.warn("OIDC identity does not match account '{}'", account.getName());
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Invalid account");
        }
        // synchronize groups
        synchronizeGroups(account, identity);
        return new SubjectAccreditedImpl((AbstractAccount) account, identity);
    }

    @Override
    public Subject authenticate(String accountName, Object credentials) throws AuthenticationException {
        if(!(credentials instanceof OidcIdentity)) {
            throw new AuthenticationException(AuthenticationException.WRONG_PASSWORD, "Could not authenticate.");
        }
        return establishSubject((OidcIdentity) credentials);
    }

    @Override
    public boolean deleteAccount(Account account) throws PermissionDeniedException, EXistException, ConfigurationException {
        throw new PermissionDeniedException("OIDC accounts are managed through the OIDC server");
    }

    @Override
    public boolean deleteGroup(Group group) throws PermissionDeniedException, EXistException, ConfigurationException {
        throw new PermissionDeniedException("OIDC groups are managed through the OIDC server");
    }

    /**
     * Creates an account from and OIDC identity if it does not exist yet
     * @param identity OIDC identity to create the account from
     * @return the account that was either found or newly created
     * @throws AuthenticationException
     */
    public Account createAccount(OidcIdentity identity) throws AuthenticationException {
        LOG.info("Starting Account Creation");
        try (DBBroker broker = getDatabase().get(java.util.Optional.of(getSecurityManager().getSystemSubject()))) {
            // Check again to avoid duplicate creation.
            Account existing = getAccount(identity.username());
            LOG.info("Checked for existing account");
            if (existing != null && !getId().equals(existing.getRealmId())) {
                LOG.error("Existing account found '{}' in realm '{}'", identity.username(), existing.getRealmId());
                throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Invalid account name");
            }
            if (existing != null) {
                LOG.info("Existing OIDC account found");
                return existing;
            }

            // Create a template for the new user
            UserAider template = new UserAider(Account.UNDEFINED_ID, getId(), identity.username());
            LOG.info("Created Aider");

            // Get the defaultGroup
            LOG.info("Defining default group " + defaultGroupName);
            Group defaultGroup = getGroup(defaultGroupName);
            LOG.info("Found default group");

            // Create default group if necessary.
            if (defaultGroup == null) {
                defaultGroup = createGroupInDatabase(broker, defaultGroupName);
                if (defaultGroup == null) {
                    throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Could not create required OIDC group: " + defaultGroupName);
                }
            }

            // Add other user groups. Create them if necessary
            Set<String> localGroups = getLocalUserGroups(identity.groups());
            for (String localGroupName : localGroups) {
                Group localGroup = getSecurityManager().getGroup(localGroupName);
                if (localGroup == null) {
                    localGroup = createGroupInDatabase(broker, localGroupName);
                    if (localGroup == null) {
                        throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Could not create required OIDC group: " + defaultGroupName);
                    }
                }
                template.addGroup(localGroup);
            }

            // Set a random password as the user is always authenticated over his token
            template.setPassword(generateRandomPassword());
            LOG.info("Generated password");
            template.addGroup(defaultGroup);
            LOG.info("group");

            // Set the account metadata for additional identification
            template.setMetadataValue(OidcSchemaType.ISSUER, identity.issuer());
            template.setMetadataValue(OidcSchemaType.SUBJECT, identity.subject());

            broker.pushSubject(getSecurityManager().getSystemSubject());
            try {
                Account created = getSecurityManager().addAccount(template);
                if (created == null || !getId().equals(created.getRealmId())) {
                    throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Account creation produced an account from an unexpected realm");
                }
                return created;
            } finally {
                broker.popSubject();
            }
        } catch (PermissionDeniedException exception) {
            LOG.error("An Exception occurred during Account Creation: ", exception);
            throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Could not create OIDC account: "+ identity.username(), exception);
        } catch (EXistException exception) {
            // EXistException could imply that an account with that name was already created by the time the creation execution finished (Racing condition)
            LOG.error("An Exception occurred during Account Creation: ", exception);
            Account concurrent = getAccount(identity.username());
            if (concurrent != null) {
                LOG.info("Account '{}' was created concurrently in realm '{}'", identity.username(), concurrent.getRealmId());
                return requireOidcAccount(concurrent);
            }
            // If it was not a duplicate-account race.
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Could not log in. Try again later or ask your administrator");
        }
    }

    /**
     * Generates a random 32 character password.
     * This is required to secure the accounts that can only be validated by OIDC so the password stored in the database is non-empty.
     * The user never gets to see the password
     * @return random password for the OIDC user in eXist-db
     */
    private static String generateRandomPassword() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Creates a group inside eXist-db if it does not already exist
     * @param broker broker used to create the group
     * @param groupname name of the new group
     * @return the group if it exists; null otherwise.
     * @throws AuthenticationException
     */
    private Group createGroupInDatabase(final DBBroker broker, final String groupname) {
        try {
            Group group = getSecurityManager().getGroup(groupname);
            if(group != null) {
                return group;
            }
            return getSecurityManager().addGroup(broker, new GroupAider(INTERNAL_REALM_ID, groupname));
        } catch (PermissionDeniedException | EXistException e) {
            LOG.error("An error occurred creating a group: ", e);
            return null;
        }
    }

    private Set<String> getLocalUserGroups(Set<String> userGroups) {
        Set<String> localUserGroups = new HashSet<String>();
        if(oidcGroups == null) {
            throw new NullPointerException("local groups must not be null");
        }
        if(userGroups == null) {
            throw new NullPointerException("User groups must not be null");
        }
        for (OidcGroupConfig oidcGroup : oidcGroups) {
            if (userGroups.contains(oidcGroup.getExternal())) {
                LOG.info("Found group " + oidcGroup);
                localUserGroups.add(oidcGroup.getLocal());
            }
        }
        return localUserGroups;
    }
    
    /**
     * Returns the input account if it is stored in this realm
     * @param account account to verify membership in this realm
     * @return the input account if its realmID equals the ID of this realm
     * @throws AuthenticationException if one of these apply:
     * <ul>
     * <li>account is null</li>
     * <li>account's realmID is not equal to the ID of this realm</li>
     * </ul>
     */
    private Account requireOidcAccount(Account account) throws AuthenticationException {
        // Make sure the account lies inside the OIDC realm
        if (account == null || !getId().equals(account.getRealmId())) {
            LOG.error("Account not found.");
            throw new AuthenticationException(AuthenticationException.ACCOUNT_NOT_FOUND, "Invalid account name");
        }
        return account;
    }

    /**
     * Synchronizes an OIDC account's group between the identity claim of the OIDC server and the local user 
     * @param account Local OIDC account that gets the groups synchronized
     * @param identity OIDC identity returned by the server
     * @return account with updated groups
     * @throws AuthenticationException if one of these apply:
     * <ul>
     * <li>any group name is null or empty</li>
     * <li>one of the local groups in the mapping is the dba group</li>
     * <li>the dbbroker cannot change the groups of the user</li>
     * </ul>
     */
    private Account synchronizeGroups(Account account, OidcIdentity identity) throws AuthenticationException{
        if (oidcGroups == null || oidcGroups.isEmpty()) {
            return account;
        }

        Set<String> removeGroups = new HashSet<String>();
        Set<String> addGroups = new HashSet<String>();

        for(OidcGroupConfig oidcGroup : oidcGroups) {
            // Make sure none of the group names is null or empty
            if (oidcGroup.getLocal() == null || oidcGroup.getLocal().trim().isEmpty() || oidcGroup.getExternal() == null || oidcGroup.getExternal().trim().isEmpty()) {
                throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Invalid OIDC group mapping");
            }
            // Make sure the local group is never the dba group
            if (oidcGroup.getLocal().equalsIgnoreCase(SecurityManager.DBA_GROUP)) {
                throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Local group must not be dba group");
            }
            // If an account has the local group, but not the external group, revoke it
            if(account.hasGroup(oidcGroup.getLocal()) && !identity.groups().contains(oidcGroup.getExternal())) {
                removeGroups.add(oidcGroup.getLocal());
            }
            // If an account has the external group, but not the local group, add it
            if(!account.hasGroup(oidcGroup.getLocal()) && identity.groups().contains(oidcGroup.getExternal())) {
                addGroups.add(oidcGroup.getLocal());
            }
        }

        // If no groups must be removed or added, avoid requesting a DBBroker
        if (addGroups.isEmpty() && removeGroups.isEmpty()) {
            return account;
        }

        // If groups need to be added or removed, do it now
        try (DBBroker broker = getDatabase().get(Optional.of(getSecurityManager().getSystemSubject()))) {
            broker.pushSubject(getSecurityManager().getSystemSubject());
            try {
                for (String newGroup: addGroups) {
                    account.addGroup(newGroup);
                }
                for (String removeGroup : removeGroups) {
                    account.remGroup(removeGroup);
                }
                getSecurityManager().updateAccount(account);
                LOG.info("Synchronized OIDC groups for account '{}'", account.getName());
            } finally {
                broker.popSubject();
            }
        return account;
        } catch (PermissionDeniedException e) {
            LOG.error("Could not synchronize groups. Permission denied.", e);
            throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Could not synchronize groups");
        } catch (EXistException e) {
            LOG.error("Could not synchronize groups.", e);
            throw new AuthenticationException(AuthenticationException.UNNOWN_EXCEPTION, "Could not synchronize OIDC groups");
        }
    }
}
