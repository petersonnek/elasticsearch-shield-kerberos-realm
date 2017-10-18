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

import org.apache.logging.log4j.Logger;

import java.util.ArrayList;

public class LDAPGroupTraverserThread implements Runnable {

    private final String distinguishedName;
    private final LDAPGroupTraverser traverser;
    private final int depth;
    private final Logger logger;

    public LDAPGroupTraverserThread(String groupDn, LDAPGroupTraverser ldapGroupTraverser, int groupDepth, Logger esLogger ){
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
            logger.debug("In group " + distinguishedName + " found nested group " +
                    grp + " adding as a nested group and finding child groups");
            if(!traverser.isInGroupList(grp)) {
                traverser.addGroupToList(grp);
                traverser.queueToTraverseChildGroup(grp, depth);
            }
        }
    }
}
