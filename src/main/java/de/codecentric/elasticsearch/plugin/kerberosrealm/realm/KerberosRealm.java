/*
   Copyright 2015 codecentric AG

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Author: Hendrik Saly <hendrik.saly@codecentric.de>
           and Apache Tomcat project https://tomcat.apache.org/ (see comments and NOTICE)
 */
package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import java.io.Serializable;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.admin.cluster.node.liveness.LivenessRequest;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.env.Environment;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.shield.InternalSystemUser;
import org.elasticsearch.shield.User;
import org.elasticsearch.shield.authc.AuthenticationToken;
import org.elasticsearch.shield.authc.Realm;
import org.elasticsearch.shield.authc.RealmConfig;
import org.elasticsearch.shield.authc.support.DnRoleMapper;
import org.elasticsearch.transport.TransportMessage;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

import com.google.common.collect.Iterators;

import de.codecentric.elasticsearch.plugin.kerberosrealm.support.JaasKrbUtil;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.KrbConstants;
import de.codecentric.elasticsearch.plugin.kerberosrealm.support.SettingConstants;

/**
 */
public class KerberosRealm extends Realm<KerberosAuthenticationToken> {

    public static final String TYPE = "cc-kerberos";

    private final boolean stripRealmFromPrincipalName;
    private final String acceptorPrincipal;
    private final Path acceptorKeyTabPath;
    private final Environment env;
    private final boolean mockMode;
    private final String roleMappingPath;

    private int ldapCacheMinutes = SettingConstants.DEFAULT_LDAP_CACHE_MINUTES;
    private int maxNestedGroupDepth = SettingConstants.DEFAULT_MAX_NESTED_GROUP_DEPTH;
    private int maxThreadsToUseToFindNestedGroups = SettingConstants.DEFAULT_MAX_THREADS_TO_USE_TO_FIND_NESTED_GROUPS;

    private final LDAPHelper ldapHelper;
    private final RoleMapper roleMapper;
    private final RoleCacheRefresher cacheRefresher;
    private final FileWatcher fileWatcher;

    public KerberosRealm(final RealmConfig config) {
        super(TYPE, config);
        stripRealmFromPrincipalName = config.settings().getAsBoolean(SettingConstants.STRIP_REALM_FROM_PRINCIPAL, true);
        acceptorPrincipal = config.settings().get(SettingConstants.ACCEPTOR_PRINCIPAL, null);
        final String acceptorKeyTab = config.settings().get(SettingConstants.ACCEPTOR_KEYTAB_PATH, null);


        roleMappingPath = DnRoleMapper.resolveFile(config.settings(), config.env()).toAbsolutePath().toString();
        logger.warn("sheild config location " + roleMappingPath);

        env = new Environment(config.globalSettings());
        mockMode = config.settings().getAsBoolean("mock_mode", false);

        if (acceptorPrincipal == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", SettingConstants.ACCEPTOR_PRINCIPAL);
        }

        if (acceptorKeyTab == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", SettingConstants.ACCEPTOR_KEYTAB_PATH);
        }

        acceptorKeyTabPath = env.configFile().resolve(acceptorKeyTab);

        if (!mockMode && (!Files.isReadable(acceptorKeyTabPath) && !Files.isDirectory(acceptorKeyTabPath))) {
            throw new ElasticsearchException("File not found or not readable: {}", acceptorKeyTabPath.toAbsolutePath());
        }

        try {
            ldapCacheMinutes = Integer.parseInt(config.settings().get(SettingConstants.LDAP_CACHE_MINUTES, "60"));
        } catch (NumberFormatException e) {
            logger.warn("Incorrect format for {}", SettingConstants.LDAP_CACHE_MINUTES);
        }
        try {
            maxNestedGroupDepth = Integer.parseInt(config.settings().get(SettingConstants.MAX_NESTED_GROUP_DEPTH, "15"));
        } catch (NumberFormatException e) {
            logger.warn("Incorrect format for {}", SettingConstants.MAX_NESTED_GROUP_DEPTH);
        }

        try {
            maxThreadsToUseToFindNestedGroups = Integer.parseInt(config.settings().get(SettingConstants.MAX_THREADS_TO_USE_TO_FIND_NESTED_GROUPS, "50"));
        } catch (NumberFormatException e) {
            logger.warn("Incorrect format for {}", SettingConstants.MAX_THREADS_TO_USE_TO_FIND_NESTED_GROUPS);
        }

        ldapHelper = new LDAPHelper(config, logger);
        roleMapper = new RoleMapper(roleMappingPath, ldapHelper, stripRealmFromPrincipalName, maxNestedGroupDepth, maxThreadsToUseToFindNestedGroups, logger);

        cacheRefresher = new RoleCacheRefresher(roleMapper, ldapCacheMinutes);
        fileWatcher = new FileWatcher(roleMappingPath, roleMapper, logger);

        Thread cacheThread = new Thread(cacheRefresher);
        Thread fileWatcherThread = new Thread(fileWatcher);
        cacheThread.start();
        fileWatcherThread.start();
    }

    @Override
    public boolean supports(final AuthenticationToken token) {
        return token instanceof KerberosAuthenticationToken;
    }

    @Override
    public KerberosAuthenticationToken token(final RestRequest request) {
        if (logger.isDebugEnabled()) {
            logger.debug("Rest request headers: {}", Iterators.toString(request.headers().iterator()));
        }
        final String authorizationHeader = request.header("Authorization");
        final KerberosAuthenticationToken token = token(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Rest request token '{}' for {} successully generated", token, request.path());
        }
        return token;
    }

    private KerberosAuthenticationToken token(final String authorizationHeader) {
        if (mockMode) {
            return tokenMock(authorizationHeader);
        } else {
            return tokenKerb(authorizationHeader);
        }
    }

    private KerberosAuthenticationToken tokenMock(final String authorizationHeader) {
        //Negotiate YYYYVVV....
        //Negotiate_c YYYYVVV.... 

        if (authorizationHeader != null && acceptorPrincipal != null) {

            if (!authorizationHeader.trim().toLowerCase(Locale.ENGLISH).startsWith("negotiate")) {
                throw new ElasticsearchException("Bad 'Authorization' header");
            } else {
                if (authorizationHeader.trim().toLowerCase(Locale.ENGLISH).startsWith("negotiate_c")) {
                    //client indicates that this is the last round of security context establishment
                    return new KerberosAuthenticationToken("finaly negotiate token".getBytes(StandardCharsets.UTF_8), "mock_principal");
                } else {
                    //client want another ound of security context establishment
                    final ElasticsearchException ee = new ElasticsearchException("MOCK TEST EXCEPTION");
                    ee.addHeader("kerberos_out_token", "mocked non _c negotiate");
                    throw ee;
                }
            }

        }

        return null;
    }

    private KerberosAuthenticationToken tokenKerb(final String authorizationHeader) {
        Principal principal = null;
        List<String> groups = null;

        if (authorizationHeader != null && acceptorKeyTabPath != null && acceptorPrincipal != null) {

            if (!authorizationHeader.trim().toLowerCase(Locale.ENGLISH).startsWith("negotiate ")) {
                throw new ElasticsearchException("Bad 'Authorization' header");
            } else {

                final byte[] decodedNegotiateHeader = DatatypeConverter.parseBase64Binary(authorizationHeader.substring(10));

                GSSContext gssContext = null;
                byte[] outToken = null;

                try {

                    final Subject subject = JaasKrbUtil.loginUsingKeytab(acceptorPrincipal, acceptorKeyTabPath, false);

                    final GSSManager manager = GSSManager.getInstance();
                    final int credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;

                    final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                        @Override
                        public GSSCredential run() throws GSSException {
                            return manager.createCredential(null, credentialLifetime, KrbConstants.SPNEGO, GSSCredential.ACCEPT_ONLY);
                        }
                    };
                    gssContext = manager.createContext(Subject.doAs(subject, action));

                    outToken = Subject.doAs(subject, new AcceptAction(gssContext, decodedNegotiateHeader));

                    if (outToken == null) {
                        logger.warn("Ticket validation not successful, outToken is null");
                        return null;
                    }

                    principal = Subject.doAs(subject, new AuthenticateAction(logger, gssContext, stripRealmFromPrincipalName));

                    groups = ldapHelper.getUserRoles(principal.getName());

                } catch (final LoginException e) {
                    logger.error("Login exception due to {}", e, e.toString());
                    throw ExceptionsHelper.convertToRuntime(e);
                } catch (final GSSException e) {
                    logger.error("Ticket validation not successful due to {}", e, e.toString());
                    throw ExceptionsHelper.convertToRuntime(e);
                } catch (final PrivilegedActionException e) {
                    final Throwable cause = e.getCause();
                    if (cause instanceof GSSException) {
                        logger.warn("Service login not successful due to {}", e, e.toString());
                    } else {
                        logger.error("Service login not successful due to {}", e, e.toString());
                    }
                    throw ExceptionsHelper.convertToRuntime(e);
                } finally {
                    if (gssContext != null) {
                        try {
                            gssContext.dispose();
                        } catch (final GSSException e) {
                            // Ignore
                        }
                    }
                    //TODO subject logout
                }

                if (principal == null) {
                    final ElasticsearchException ee = new ElasticsearchException("Principal null");
                    ee.addHeader("kerberos_out_token", DatatypeConverter.printBase64Binary(outToken));
                    throw ee;
                }

                final String username = ((SimpleUserPrincipal) principal).getName();
                return new KerberosAuthenticationToken(outToken, username, groups);
            }

        } else {
            return null;
        }
    }

    @Override
    public KerberosAuthenticationToken token(final TransportMessage<?> message) {

        if (logger.isDebugEnabled()) {
            logger.debug("Transport request headers: {}", message.getHeaders());
        }

        if (message instanceof LivenessRequest) {
            return KerberosAuthenticationToken.LIVENESS_TOKEN;
        }

        final String authorizationHeader = message.getHeader("Authorization");
        final KerberosAuthenticationToken token = token(authorizationHeader);
        if (token != null && logger.isDebugEnabled()) {
            logger.debug("Transport message token '{}' for message {} successully generated", token, message.getClass());
        }
        return token;
    }

    @Override
    public User authenticate(final KerberosAuthenticationToken token) {

        if(token == KerberosAuthenticationToken.LIVENESS_TOKEN) {
            return InternalSystemUser.INSTANCE;
        }

        final String actualUser = token.principal();
        final List<String> actualGroups = token.groups();

        if (actualUser == null || actualUser.isEmpty() || token.credentials() == null) {
            logger.warn("User '{}' cannot be authenticated", actualUser);
            return null;
        }

        String[] userRoles = new String[0];
        List<String> userRolesList = roleMapper.rolesMap.get(actualUser);
        
              
        if(actualGroups != null){                
            for(String group: actualGroups){
                if(roleMapper.groupMap.containsKey(group)){
                    for(String role:roleMapper.groupMap.get(group)){
                        if(!userRolesList.contains(role)){
                            userRolesList.add(role);
                        }
                    }
                    logger.debug("User '{}' found in AD group {} mapping to shield role {}", actualUser, group, Arrays.toString(roleMapper.groupMap.get(group).toArray(new String[0])));
                }
            }
        }
        
        if(userRolesList != null && !userRolesList.isEmpty()) {
            userRoles = userRolesList.toArray(new String[0]);
        }
        
        logger.debug("User '{}' with roles {} successully authenticated", actualUser, Arrays.toString(userRoles));
        return new User(actualUser, userRoles);
    }

    @Override
    public User lookupUser(final String username) {
        return null;
    }

    @Override
    public boolean userLookupSupported() {
        return false;
    }

    /**
     * This class gets a gss credential via a privileged action.
     */
    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AcceptAction implements PrivilegedExceptionAction<byte[]> {

        GSSContext gssContext;

        byte[] decoded;

        AcceptAction(final GSSContext context, final byte[] decodedToken) {
            this.gssContext = context;
            this.decoded = decodedToken;
        }

        @Override
        public byte[] run() throws GSSException {
            return gssContext.acceptSecContext(decoded, 0, decoded.length);
        }
    }

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static class AuthenticateAction implements PrivilegedAction<Principal> {

        private final ESLogger logger;
        private final GSSContext gssContext;
        private final boolean strip;

        private AuthenticateAction(final ESLogger logger, final GSSContext gssContext, final boolean strip) {
            super();
            this.logger = logger;
            this.gssContext = gssContext;
            this.strip = strip;
        }

        @Override
        public Principal run() {
            return new SimpleUserPrincipal(getUsernameFromGSSContext(gssContext, strip, logger));
        }
    }

    //borrowed from Apache Tomcat 8 http://svn.apache.org/repos/asf/tomcat/tc8.0.x/trunk/
    private static String getUsernameFromGSSContext(final GSSContext gssContext, final boolean strip, final ESLogger logger) {
        if (gssContext.isEstablished()) {
            GSSName gssName = null;
            try {
                gssName = gssContext.getSrcName();
            } catch (final GSSException e) {
                logger.error("Unable to get src name from gss context", e);
            }

            if (gssName != null) {
                String name = gssName.toString();

                return stripRealmName(name, strip);

            }
        }

        return null;
    }

    private static String stripRealmName(String name, boolean strip){
        if (strip && name != null) {
            final int i = name.indexOf('@');
            if (i > 0) {
                // Zero so we don;t leave a zero length name
                name = name.substring(0, i);
            }
        }

        return name;
    }

    private static class SimpleUserPrincipal implements Principal, Serializable {

        private static final long serialVersionUID = -1;
        private final String username;

        SimpleUserPrincipal(final String username) {
            super();
            this.username = username;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((username == null) ? 0 : username.hashCode());
            return result;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final SimpleUserPrincipal other = (SimpleUserPrincipal) obj;
            if (username == null) {
                if (other.username != null) {
                    return false;
                }
            } else if (!username.equals(other.username)) {
                return false;
            }
            return true;
        }

        @Override
        public String getName() {
            return this.username;
        }

        @Override
        public String toString() {
            final StringBuilder buffer = new StringBuilder();
            buffer.append("[principal: ");
            buffer.append(this.username);
            buffer.append("]");
            return buffer.toString();
        }
    }
}
