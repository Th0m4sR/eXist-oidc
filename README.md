# eXist-oidc

This repository provides code for an eXist-db realm and filters to secure eXist-db using the OpenID Connect (OIDC) protocol for Keycloak.
The current implementation only supports Keycloak but should be easily extendable to support further OIDC servers.
The version here was implemented and tested on eXist-db 6.4.1.
The implementation is based on pac4j and Java 8.

This project implements two parts:

- An eXist-db realm that authenticates users using the username and a token from an OIDC server
- An example configuration for a filter that secures an application using either OIDC or basic authentication.

For the OIDC realm, you can reuse the existing implementation for Keycloak or implement the `OidcTokenValidator` interface yourselbf for other servers.

The configuration factory, filters and matchers can be any pac4j implementation and you might configure them yourself.
For the context in which I originally implemented this project, I needed both Basic auth to eXist-db and OIDC to secure my application, so my ConfigFactory uses the BasucAuthMatcher.

**Hint: This is a very basic implementation for securing your eXist-db apps with Keycloak and might not support all functionalities that you need**

The test cases currently only cover most of the realm and not the filters.

Parts of the code have been generated using AI. This holds particularly for the test cases.
I reviewed every part of the code to the best of my knowledge and understanding of the pac4j documentation and eXist-db but I cannot guarantee production security, so be careful when using this repository.
If you find any problems, let me know in the issues.

The `docker-compose.yml` is only for the demo and not part of the actual plugin.

# How the Realm Works

Please read this section before using the code as it also discusses the security concerns that I am currently aware of.

The `OidcRealm` implements the `authenticate` method in a way that it takes an `OidcIdentity` which is built from a pac4j OidcProfile.
The `OidcProfile` is created by the pac4j filters and passed through the `OidcLoginSubjectFilter`.

Keycloak-side session revocation and account changes are not detected until the current access token expires or is refreshed.
So if your OIDC user is currently in a session on eXist-db and you change his permissions, the changes only apply after the access token expired or is refreshed.
Also, for access tokens, possession is considered proof for authentication in OIDC as they are bearer tokens.
Authentication will fail if the username in the login does not match the username in the OIDC access token claim.

Inside the Security configuration (see below), you can match external groups from your OIDC server to local groups.

If an internal group that you define inside this configuration does not already exist inside eXist-db, it will be created.
Because your application might already have some groups configured, all groups for the realm are actually stored inside the internal realm of eXist-db.
This also holds for groups that are newly created.
Users, however, are still stored under the `/db/system/security/Oidc/accounts` collection.

Users are always provisioned to eXist-db to make working with the ACL permsission easier.

In case you want to secure an application over this module, the current workflow is that you set up the session using the user that is authenticated in the security manager.

Because the OIDC login is ensured over a filter, the `OidcLoginSubjectFilter` creates a subject per request, using the `establishSubject` method of the `OidcRealm`.

To authenticate the user to your application, you must configure it to use the current subject to authorize the user.
The demo includes an example of how this is done in TEI Publisher.

When an OIDC group mapping is removed, the administrator must also remove the corresponding local group membership from existing OIDC accounts if this is desired.
The realm will not handle this on its own.

Also, it is assumed that your OIDC users are managed and cannot register themselves.
Every OIDC login might trigger a local account creation, so in case your OIDC users can register themselves, they could flood your eXist-db with registering requests.

Be careful with using existing group names inside the mapping from OIDC to eXist-db groups as groups might own collections and you could give your OIDC users access to existing collections.
This is intended behavior but you should still be aware of this.

Collisions with existing account names can occur, but the code should make sure that every retrieved account belongs to the OIDC realm by checking the realm ID of the user.
Intended behavior is that in case of collisions, the user gets an authentication exception.
This implies that, if you have a user with the same name inside the exist realm, an OIDC user with that name cannot log in.

In case a user logs in and none of the OIDC group to eXist-db group mappings apply, he will still be registered, but get assigned the role you configure under the "default-role" attribute in the security configuration.

# Demo

This repository contains a demo to see the realm in action on a TEI Publisher application.

To run the demo, you must first build the realm and afterwards start the docker-compose project:

```Bash
cd exist-oidc
mvn clean package
cd ..
docker compose up -d --build
```

Wait until the Keycloak logs mention "Added oidc-demo to /KeycloakTEI" to be sure the setup for the demo was completed.
If you try to log in too early, the access token will not include the group for this user and you will run into the issue mentioned in the previous section.
You can mitigate this then by clearing your browser cache / cookies or opening a new incognito tab.

Check out the README in the demo directory to see how the application is configured and how to log in to the demo application.

# Setup

This section describes how to build and use the code in this repository.

## Building

You can build the project by switching to the `exist-oidc` directory and running `mvn clean package`.
The project was originally compiled using Java 8.

```Bash
cd exist-oidc
mvn clean package
```

To protect your application, you secure it the way you secure any application with pac4j.
Refer to their resources for more information https://github.com/pac4j/jee-pac4j.
Here, the `web.xml` configuration is used as eXist-db's `web.xml` can be easily extended using that method

## Installation

Put the output jar you built under `target/exist-oidc-realm-0.1.0-SNAPSHOT.jar` into a file location that is configured under your eXist-db's classpath, so eXist-db is able to find the realm and the configuration and filters.

### web.xml

Here, the `web.xml` configuration for pac4j is used as eXist-db's `web.xml` can be easily extended using that method
The configuration you find in this repository works by adding the filters and filter to the `web.xml`
```XML
...
   <!-- ============================================================= -->
   <!-- OIDC filter definitions                                       -->
   <!-- ============================================================= -->
   <filter>
      <filter-name>oidcSecurityFilter</filter-name>
      <filter-class>org.pac4j.jee.filter.SecurityFilter</filter-class>
      <init-param>
         <param-name>configFactory</param-name>
         <param-value>org.exist.security.realm.oidc.OidcConfigFactory</param-value>
      </init-param>
      <init-param>
         <param-name>clients</param-name>
         <param-value>existOidcClient,existBasicClient</param-value>
      </init-param>
      <!--
      <init-param>
         <param-name>authorizers</param-name>
         <param-value>isAuthenticated</param-value>
      </init-param>
      -->
      <init-param>
         <param-name>authorizers</param-name>
         <param-value>roleAuthorizer</param-value>
      </init-param>
   </filter>

   <filter>
      <filter-name>oidcCallbackFilter</filter-name>
      <filter-class>org.pac4j.jee.filter.CallbackFilter</filter-class>
      <init-param>
         <param-name>defaultUrl</param-name>
         <param-value>/exist/apps/oidc/</param-value>
      </init-param>
      <init-param>
         <param-name>defaultClient</param-name>
         <param-value>existOidcClient</param-value>
      </init-param>
      <init-param>
         <param-name>renewSession</param-name>
         <param-value>true</param-value>
      </init-param>
   </filter>

   <filter>
      <filter-name>oidcLogoutFilter</filter-name>
      <filter-class>org.pac4j.jee.filter.LogoutFilter</filter-class>
      <init-param>
         <param-name>config</param-name>
         <param-value>org.exist.security.realm.oidc.OidcConfigFactory</param-value>
      </init-param>

      <init-param>
         <param-name>defaultUrl</param-name>
         <param-value>/exist</param-value>
      </init-param>
      <init-param>
         <param-name>localLogout</param-name>
         <param-value>true</param-value>
      </init-param>
      <!-- Enable later when provider logout works. -->
      <init-param>
         <param-name>destroySession</param-name>
         <param-value>true</param-value>
      </init-param>
      <init-param>
         <param-name>centralLogout</param-name>
         <param-value>true</param-value>
      </init-param>
   </filter>
   <filter>
      <filter-name>oidcLoginSubjectFilter</filter-name>
      <filter-class>org.exist.security.realm.oidc.OidcLoginSubjectFilter</filter-class>
   </filter>

      <!-- ============================================================= -->
      <!-- OIDC filter mappings                                          -->
      <!-- ============================================================= -->
      <filter-mapping>
         <filter-name>oidcCallbackFilter</filter-name>
         <url-pattern>/oidc/callback</url-pattern>
         <dispatcher>REQUEST</dispatcher>
      </filter-mapping>
      <filter-mapping>
         <filter-name>oidcLogoutFilter</filter-name>
         <url-pattern>/oidc/logout</url-pattern>
         <dispatcher>REQUEST</dispatcher>
      </filter-mapping>
      <filter-mapping>
         <filter-name>oidcSecurityFilter</filter-name>
         <url-pattern>/apps/oidc/*</url-pattern>
         <dispatcher>REQUEST</dispatcher>
      </filter-mapping>
      <filter-mapping>
      <filter-name>oidcLoginSubjectFilter</filter-name>
      <url-pattern>/apps/oidc/*</url-pattern>
      <dispatcher>REQUEST</dispatcher>
   </filter-mapping>
...
```

You can also add more security by setting the Same-Site, HTTP Only, and Secure Attributes to the session cookie inside your `web.xml`

```XML
   <session-config>
      <cookie-config>
         <http-only>true</http-only>
         <secure>true</secure>
         <comment>__SAME_SITE_LAX__</comment>
      </cookie-config>
   </session-config>
```

As always in your eXist-db setup, your `web.xml` must live under `${EXIST_HOME}/etc/web.xml`

For the OIDC filter to work properly, you must configure it aforehand.

To so, add a `oidc.properties` file to the same path: `${EXIST_HOME}/etc/oidc.properties` and set these variables:

### oidc.properties

```properties
oidc.clientId=your-keycloak-client-id
oidc.discoveryUri=https://your-keycloak-server/realms/<your-realm>/.well-known/openid-configuration
oidc.callbackUrl=https://your-exist-server/exist/oidc/callback
# oidc.secret=...   only for a confidential client
oidc.allowedGroups=/KeycloakGroup1,/KeycloakGroup2
local.allowedGroups=LocalGroup1,LocalGroup2
```

The local.allowedGroups are used for the basic auth client. If the credentials do not match any of the `local.allowedGroups`, the user will also get a 403.

### Security Configuration

Once you configured these files, you need to register the realm inside the security collection.
To do so, boot up your eXist-db instance, log in to exide and navigate to the config file under `/db/system/security/config.xml`.

The configured file could look something like that in case you only have the default eXist-db realm besides the new one:

```XML
<security-manager xmlns="http://exist-db.org/Configuration" version="2.1">
    <authentication-entry-point>/authentication/login</authentication-entry-point>
    <realm id="Oidc" version="1.0" issuer="https://your-keycloak-instance/<your-realm>" audience="account" usernameClaim="preferred_username" groupsClaim="groups" defaultGroupName="guest" clientId="your-keycloak-client">
        <group external="/Your_Keycloak_Group" local="your-local-group"></group>
        <!-- You can add more group mappings here -->
    </realm>
<!--<events></events>-->
</security-manager>
```

There is a known bug on group provisioning when multiple OIDC groups are mapped to the same internal group.
Right now, the mapping only works reliably when each local group has exactly one external group inside the group mapping.

### Keycloak Setup

The current implementation expects a claim named `groups` to map the groups.
This claim is not provided by default.
To add this, you must map your Keycloak roles to this claim.
You can do this by adding a group-role-mapper in Keycloak.

This configuration is found when you select your Keycloak realm in the admin UI, go to your client and select `Client -> Client Scopes -> <client-name>-dedicated -> Mappers -> Group Mapper`

# Debugging

If you want to debug your configuration, you can try out these things.

## Basic Auth in eXist-db

You can try out if basic auth works on your client using

```Bash
curl -Lkv --user "admin:" http://localhost:8555/exist/apps/your-exist-app
```

If the user does not have one of the allowed roles of the `local.allowedGroups` property (which can also be a comma-separated list of groups), you will however get a 403 error.

## Inspect OIDC Token

You can try to get a token from Keycloak using this command:

```Bash
curl -s -X POST \
  "https://your-keycloak-url/realms/<your-realm>/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=<your-keycloak-client>" \
  -d "username=<your-keycloak-user>" \
  -d "password=<your-keycloak-password>" \
  -d "grant_type=password" \
  -d "client_secret=<your-keycloak-secret-if-configured>"
```

To inspect your token, you can use e.g. jwt.io
