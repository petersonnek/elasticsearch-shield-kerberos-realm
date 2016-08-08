package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.common.logging.ESLogger;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class LDAPGroupTraverser {

    private final String distinguishedName;
    public final LDAPHelper ldapHelper;
    public final int maxGroupDepth;
    private ExecutorService execService;
    public final Collection<String> groups = Collections.synchronizedSet(new HashSet<String>());
    private final Collection<Future> futures = Collections.synchronizedSet(new HashSet<Future>());
    private final ESLogger logger;

    public LDAPGroupTraverser(String groupDn, LDAPHelper LdapHelper, int maxGroupDepthToTraverse, int maxThreadsToUse, ESLogger esLogger){
        distinguishedName = groupDn;
        ldapHelper = LdapHelper;
        maxGroupDepth = maxGroupDepthToTraverse;
        execService = Executors.newFixedThreadPool(maxThreadsToUse, new LDAPGroupTraverserThreadFactory("LDAPGroupTraverser"));
        logger = esLogger;
    }

    public void queueToTraverseChildGroup(String groupDn, int currentDepth){
        if(currentDepth <= maxGroupDepth) {
            startNewThread(groupDn, currentDepth);
        }
    }

    private void startNewThread(String groupDn, int depth) {
         futures.add(execService.submit(new LDAPGroupTraverserThread(groupDn, this, depth, logger)));
    }

    public void startTraversing() {
        startNewThread(this.distinguishedName, 1);
    }

    public void addGroupToList(String groupsDn){
        groups.add(groupsDn);
    }

    public boolean isTraversingComplete(){
        synchronized(futures) {
            for (Future f : futures) {
                if (!f.isDone() && !f.isCancelled()) {
                    return false;
                }
            }
        }
        return true;
    }

    public void cleanUp(){
        if(!execService.isShutdown() || !execService.isTerminated()){
            execService.shutdown();
        }
    }

}
