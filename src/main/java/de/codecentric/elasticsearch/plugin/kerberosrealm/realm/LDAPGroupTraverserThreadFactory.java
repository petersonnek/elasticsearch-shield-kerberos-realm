package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import java.util.concurrent.ThreadFactory;

public class LDAPGroupTraverserThreadFactory implements ThreadFactory {
    private int counter = 0;
    private String prefix = "";

    public LDAPGroupTraverserThreadFactory(String prefix){
        this.prefix = prefix;
    }

    @Override
    public Thread newThread(Runnable r) {
        return new Thread(r, prefix + "-" + counter++);
    }
}
