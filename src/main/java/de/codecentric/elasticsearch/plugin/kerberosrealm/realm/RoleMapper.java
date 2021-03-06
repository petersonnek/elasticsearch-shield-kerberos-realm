package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLogger;
import org.yaml.snakeyaml.Yaml;

import javax.naming.NamingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Map;

@SuppressForbidden(
        reason = "Loading Shiled role_mapping.yml file with io.File"
)
public class RoleMapper {
    private final ESLogger logger;
    private final boolean _stripRealmFromPrincipalName;
    // maps principal string to shield role
    public ListMultimap<String, String> rolesMap = ArrayListMultimap.create();
    // maps group string to shield role
    public ListMultimap<String, String> groupMap = ArrayListMultimap.create();

    private final int maxNestedGroupDepth;
    private final int maxThreadsToUseToFindNestedGroups;

    private final String _roleMappingFilePath;
    private LDAPHelper _ldapHelper;
    private Object rolesLock = new Object();
    private Object groupLock = new Object();

    public RoleMapper(String roleMappingFilePath, LDAPHelper ldapHelper, boolean stripRealmFromPrincipalName, int maxGroupDepth, int maxThreads, ESLogger esLogger){
        _roleMappingFilePath = roleMappingFilePath;
        _ldapHelper = ldapHelper;
        _stripRealmFromPrincipalName = stripRealmFromPrincipalName;
        maxNestedGroupDepth = maxGroupDepth;
        maxThreadsToUseToFindNestedGroups = maxThreads;
        logger = esLogger;
    }


    public void LoadRoles(){
        // maps principal string to shield role
        ListMultimap<String, String> tempRolesMap = ArrayListMultimap.create();
        // maps group string to shield role
        ListMultimap<String, String> tempGroupMap = ArrayListMultimap.create();
        Yaml yaml = new Yaml();
        InputStream in = null;
        try {
            in = new FileInputStream(new File(_roleMappingFilePath));
            Map<String, ArrayList<String>> roleGroups = (Map<String, ArrayList<String>>) yaml.load(in);

            if(roleGroups != null) {
                logger.debug("Starting, add roles");
                for(String roleGroup:roleGroups.keySet()) {
                    logger.debug("Found Elastic role: " + roleGroup);
                    for(String principalOrGroup:roleGroups.get(roleGroup)) {
                        String cleanPrincipalOrGroup = principalOrGroup.replace("\"", "");
                        logger.debug("Found AD object in role Role: " + roleGroup + " AD Object: " + cleanPrincipalOrGroup);
                        String groupSid;
                        javax.naming.directory.Attributes atts = _ldapHelper.getADObjectAttributes(cleanPrincipalOrGroup);
                        if(atts != null){
                        if (atts.get("objectClass").contains("group")) {
                            groupSid = _ldapHelper.getSidFromGroup(cleanPrincipalOrGroup);
                            logger.debug("Adding group to Role: " + roleGroup + " Group: " + cleanPrincipalOrGroup);
                            tempGroupMap.put(cleanPrincipalOrGroup, roleGroup);
                            for (String nestedGroup : _ldapHelper.getNestedGroupsInGroup(cleanPrincipalOrGroup, maxNestedGroupDepth, maxThreadsToUseToFindNestedGroups)) {
                                logger.debug("Adding nested group to Role: " + roleGroup + " Group: " + nestedGroup);
                                tempGroupMap.put(nestedGroup, roleGroup);
                            }
                            logger.debug("Found group " + cleanPrincipalOrGroup + ":" + groupSid);
                        } else {
                            logger.debug("Adding User to Role: " + roleGroup + " User: " + cleanPrincipalOrGroup);
                            try {
                                tempRolesMap.put(stripRealmName(atts.get("userprincipalname").get().toString(), _stripRealmFromPrincipalName), roleGroup);
                            } catch (NamingException e) {
                                logger.debug("Failed to get group SID " + cleanPrincipalOrGroup + " " + e);
                            }
                        }
                    } else {
                        logger.warn("RoleMapper could not find " + cleanPrincipalOrGroup );

                        }
                    }
                }
            }

        } catch (IOException e) {
                        logger.warn("RoleMapper had issues mapping roles", e);
        } catch (InterruptedException e) {
                        logger.warn("RoleMapper had issues mapping roles", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception e) {
                    // no-op
                }
            }
        }
        synchronized(rolesLock) {
            rolesMap = tempRolesMap;
        }

        synchronized(groupLock) {
            groupMap = tempGroupMap;
        }
        logger.debug("Parsed roles: {}", rolesMap);
    }

    private String stripRealmName(String name, boolean strip){
        if (strip && name != null) {
            final int i = name.indexOf('@');
            if (i > 0) {
                // Zero so we don;t leave a zero length name
                name = name.substring(0, i);
            }
        }

        return name;
    }

}
