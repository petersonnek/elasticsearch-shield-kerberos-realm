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
 */

package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import de.codecentric.elasticsearch.plugin.kerberosrealm.support.SettingConstants;
import org.elasticsearch.ElasticsearchException;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.xpack.security.authc.RealmConfig;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Locale;

public class LDAPHelper {

    private final String keyStorePath;
    private final String keyStorePassword;
    private final String ldapUser;
    private final String ldapPassword;
    private final String ldapConnectionString;
    private final String ldapDomain;

    private final Logger logger;

    public LDAPHelper(RealmConfig config, Logger esLogger ){
        Settings settings = config.settings();
        logger = esLogger;

        ldapConnectionString = settings.get(SettingConstants.LDAP_URL);
        ldapDomain = settings.get(SettingConstants.LDAP_DOMAIN);
        ldapUser = settings.get(SettingConstants.LDAP_USER, null);
        ldapPassword = settings.get(SettingConstants.LDAP_PASSWORD, null);

        logger.debug("ldapDomain Path: {}", ldapDomain);
        //logger.debug("ldapGroupBase: {}", ldapGroupBase);
        logger.debug("ldapConnectionString: {}", ldapConnectionString);


        keyStorePath = config.globalSettings().get(SettingConstants.KEYSTORE_PATH, null);
        keyStorePassword = config.globalSettings().get(SettingConstants.KEYSTORE_PASSWORD, null);

        logger.debug("KeyStore Path: {}", keyStorePath);

        if (keyStorePath == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", SettingConstants.KEYSTORE_PATH);
        }

        if (keyStorePassword == null) {
            throw new ElasticsearchException("Unconfigured (but required) property: {}", SettingConstants.KEYSTORE_PASSWORD);
        }
    }


    public javax.naming.directory.Attributes getADObjectAttributes(String distinguishedName){
        Hashtable<String, Object> env = new Hashtable<>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.ldap.factory.socket", TrustAllSSLSocketFactory.class.getName());
        env.put("javax.net.ssl.keyStore", keyStorePath);
        env.put("javax.net.ssl.keyStorePassword", keyStorePassword);

        if(ldapUser != null && ldapPassword != null){
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUser);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            logger.debug("Connecting to LDAP with username: {}", ldapUser);
        }else{
            env.put(Context.SECURITY_AUTHENTICATION, "none");
            logger.debug("Attempting anonymous bind");
        }

        env.put(Context.PROVIDER_URL, ldapConnectionString);
        env.put("java.naming.ldap.attributes.binary", "objectSID");

        // Grab the current classloader to restore after loading custom sockets in JNDI context
        ClassLoader cl = Thread.currentThread().getContextClassLoader();

        DirContext ctx = null;
        try {

            Thread.currentThread().setContextClassLoader(TrustAllSSLSocketFactory.class.getClassLoader());
            // Create initial context
            ctx = new InitialDirContext(env);

            return ctx.getAttributes(distinguishedName);


        } catch (NamingException e) {
            logger.error("Could not connect to LDAP with provided method", e);
        } finally {
            if(ctx != null){
                try {
                    ctx.close();
                } catch (NamingException e) {
                    // pass
                }
            }
            Thread.currentThread().setContextClassLoader(cl);
        }
        return null;
    }

    public String getSidFromGroup(String distinguishedName){
        try {
            javax.naming.directory.Attributes attributes = getADObjectAttributes(distinguishedName);
            if(attributes != null) {
                byte[] sidbytes = null;
                sidbytes = (byte[])attributes.get("objectSid").get();
                return decodeSID(sidbytes);
            }
        } catch (NamingException e) {
            logger.error("Error retrieving sid from distinguished name '{}' : {}", distinguishedName, e);
        }
        return null;
    }

    public ArrayList<String> getMemberGroups(String groupDistinguishedName){
                        logger.debug("Getting member groups in Group " + groupDistinguishedName);
        ArrayList<String> nestedGroups = new ArrayList<String>();

        String query = "(&(objectClass=group)(memberOf=" + groupDistinguishedName + "))";

        try{
            NamingEnumeration<SearchResult> result = queryLdap(query);
            //javax.naming.directory.Attributes
            while(result != null && result.hasMore()){
                SearchResult group = result.nextElement();
                String nestedGroupDistinguishedName = group.getAttributes().get("distinguishedname").get().toString();
                nestedGroups.add(nestedGroupDistinguishedName);
            }
        }catch (Exception e){
                        logger.warn("Error occurred filtering user groups " + e);
        }

        return nestedGroups;
    }

    public String[] getNestedGroupsInGroup(String groupDistinguishedName, int maxDepth, int maxThreads) throws InterruptedException {
        LDAPGroupTraverser traverser = new LDAPGroupTraverser(groupDistinguishedName, this,maxDepth,maxThreads,logger);
        traverser.startTraversing();
        while (!traverser.isTraversingComplete()) {
            // do nothing
            Thread.sleep(50);
        }
        traverser.cleanUp();
        return Arrays.copyOf(traverser.groups.toArray(), traverser.groups.toArray().length, String[].class);
    }

    public ArrayList<String> getUserRoles(String sAMAccountName){
        ArrayList<String> groups = new ArrayList<String>();
        String query = "(&(objectClass=user)(sAMAccountName=" + sAMAccountName + "))";

        try{
            NamingEnumeration<SearchResult> result = queryLdap(query);
            //javax.naming.directory.Attributes
            if(result != null && result.hasMore()){
                SearchResult user = result.nextElement();
                javax.naming.directory.Attributes userAttributes = user.getAttributes();
                javax.naming.directory.Attribute memberobAttribute =  userAttributes.get("memberof");

                NamingEnumeration<?> memberGroups = memberobAttribute.getAll();
                while (memberGroups.hasMore() ) {
                    String group = memberGroups.next().toString();
                    if(!groups.contains(group)){
                        logger.debug("User {} in LDAP group {}", sAMAccountName, group);
                        groups.add(group.toLowerCase(Locale.ENGLISH));
                    }
                }
            }
        }catch (Exception e){
            logger.warn("Error occurred filtering user groups", e);
        }

        return groups;
    }

    private NamingEnumeration<SearchResult> queryLdap(String query){
        Hashtable<String, Object> env = new Hashtable<String, Object>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.ldap.factory.socket", TrustAllSSLSocketFactory.class.getName());
        env.put("javax.net.ssl.keyStore", keyStorePath);
        env.put("javax.net.ssl.keyStorePassword", keyStorePassword);

        if(ldapUser != null && ldapPassword != null){
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUser);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
            logger.debug("Connecting to LDAP with username: {}", ldapUser);
        }else{
            env.put(Context.SECURITY_AUTHENTICATION, "none");
            logger.debug("Attempting anonymous bind");
        }

        env.put(Context.PROVIDER_URL, ldapConnectionString);
        env.put("java.naming.ldap.attributes.binary", "objectSID");

        ArrayList<String> formatedDomain = new ArrayList<String>();
        for(String dc:(ldapDomain.split("\\."))){
            formatedDomain.add("DC=" + dc + ",");
        }
        String searchBase = "";
        for (String aFormatedDomain : formatedDomain) {
            searchBase += aFormatedDomain;
        }
        searchBase = searchBase.substring(0,  searchBase.length()-1);
        logger.debug("Search base {}", searchBase);

        // Grab the current classloader to restore after loading custom sockets in JNDI context
        ClassLoader cl = Thread.currentThread().getContextClassLoader();

        DirContext ctx = null;
        try {

            Thread.currentThread().setContextClassLoader(TrustAllSSLSocketFactory.class.getClassLoader());
            // Create initial context
            ctx = new InitialDirContext(env);


            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            return ctx.search(searchBase, query, searchControls);

        } catch (NamingException e) {
            logger.error("Could not connect to LDAP with provided method", e);
        } finally {
            if(ctx != null){
                try {
                    ctx.close();
                } catch (NamingException e) {
                    // pass
                }
            }
            Thread.currentThread().setContextClassLoader(cl);
        }
        return null;
    }

    public boolean isInRole(String group, String principal){
        String query = "(&(objectClass=user)(sAMAccountName=" + principal + ")(memberOf:1.2.840.113556.1.4.1941:=" + group + "))";
        logger.debug("isInRole query: " + query);
        NamingEnumeration<SearchResult> results = queryLdap(query);
        try{
            logger.debug("isInRole hasMoreElements: " + results.hasMoreElements());
            return results.hasMoreElements();
        } catch(Exception e){
            return false;
        }
    }

    /*
      * The binary data is in the form:
      * byte[0] - revision level
      * byte[1] - count of sub-authorities
      * byte[2-7] - 48 bit authority (big-endian)
      * and then count x 32 bit sub authorities (little-endian)
      *
      * The String value is: S-Revision-Authority-SubAuthority[n]...
      *
      * Based on code from here - http://forums.oracle.com/forums/thread.jspa?threadID=1155740&tstart=0
      */
    private String decodeSID(byte[] sid) {

        final StringBuilder strSid = new StringBuilder("S-");

        // get version
        final int revision = sid[0];
        strSid.append(Integer.toString(revision));

        //next byte is the count of sub-authorities
        final int countSubAuths = sid[1] & 0xFF;

        //get the authority
        long authority = 0;
        //String rid = "";
        for(int i = 2; i <= 7; i++) {
            authority |= ((long)sid[i]) << (8 * (5 - (i - 2)));
        }
        strSid.append("-");
        strSid.append(Long.toHexString(authority));

        //iterate all the sub-auths
        int offset = 8;
        int size = 4; //4 bytes for each sub auth
        for(int j = 0; j < countSubAuths; j++) {
            long subAuthority = 0;
            for(int k = 0; k < size; k++) {
                subAuthority |= (long)(sid[offset + k] & 0xFF) << (8 * k);
            }

            strSid.append("-");
            strSid.append(subAuthority);

            offset += size;
        }

        return strSid.toString();
    }

}
