package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.common.logging.ESLogger;

import java.util.ArrayList;

public class LDAPGroupTraverserThread implements Runnable {

    private final String distinguishedName;
    private final LDAPGroupTraverser traverser;
    private final int depth;
    private final ESLogger logger;

    public LDAPGroupTraverserThread(String groupDn, LDAPGroupTraverser ldapGroupTraverser, int groupDepth, ESLogger esLogger ){
        distinguishedName = groupDn;
        traverser = ldapGroupTraverser;
        depth = groupDepth;
        logger = esLogger;
    }

    public void run() {
        getNestedGroups(distinguishedName);
    }

    private void getNestedGroups(String groupDn){
        ArrayList<String> groups = traverser.ldapHelper.getMemberGroups(groupDn);
        for(String grp:groups){
            logger.debug("In group " + distinguishedName + " found nested group " + grp + " adding as a nested group and finding child groups");
            traverser.addGroupToList(grp);
            traverser.queueToTraverseChildGroup(grp, depth);
        }
    }
}
