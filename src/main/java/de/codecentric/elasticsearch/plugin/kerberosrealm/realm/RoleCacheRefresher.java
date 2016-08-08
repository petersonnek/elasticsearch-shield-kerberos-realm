package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;


public class RoleCacheRefresher implements Runnable{

    private final RoleMapper _roleMapper;
    private final int _cacheMinutes;

    public RoleCacheRefresher(RoleMapper roleMapper, int cacheMinutes){
        _roleMapper = roleMapper;
        _cacheMinutes = cacheMinutes;
    }

    public void run() {
        long cacheMilliseconds = _cacheMinutes * 60 * 1000;
        while(!Thread.interrupted()) {
           try{
                _roleMapper.LoadRoles();
                Thread.sleep(cacheMilliseconds);
           } catch (InterruptedException e) {
                // We've been interrupted: no more messages.
                return;
           }
        }
    }
}
