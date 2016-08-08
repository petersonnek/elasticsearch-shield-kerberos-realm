package de.codecentric.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.logging.ESLogger;

import java.io.IOException;
import java.nio.file.*;

import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

@SuppressForbidden(
        reason = "Need to do file watching"
)
public class FileWatcher implements Runnable{
    private final String _roleMappingFilePath;
    private final RoleMapper _roleMapper;
    private final ESLogger logger;

    public FileWatcher(String roleMappingFilePath, RoleMapper roleMapper, ESLogger esLogger){
        _roleMappingFilePath = roleMappingFilePath;
        _roleMapper = roleMapper;
        logger = esLogger;
    }

    public void run() {
        try {
            WatchService watcher = FileSystems.getDefault().newWatchService();
            Path dir = Paths.get(_roleMappingFilePath);
            // get the parent buecause we're asking for the actual role_mapping.yml file name
            dir.getParent().register(watcher, ENTRY_MODIFY);

            logger.warn("Watch Service registered for dir: " + dir.getFileName());

            while(!Thread.interrupted()) {
                WatchKey key;
                try {
                    key = watcher.take();
                } catch (InterruptedException ex) {
                    return;
                }

                for (WatchEvent<?> event : key.pollEvents()) {

                    if(Thread.interrupted()){
                        return;
                    }

                    @SuppressWarnings("unchecked")
                    WatchEvent<Path> ev = (WatchEvent<Path>) event;

                    // there are other sheild config files, only reload
                    // if the role_mapping file was updated
                    if(ev.context().endsWith("role_mapping.yml")){
                        logger.warn("File Watcher started reloading roles");
                        _roleMapper.LoadRoles();
                        logger.warn("File Watcher completed reloading roles");
                    }
                }

                boolean valid = key.reset();
                if (!valid) {
                    break;
                }
            }

            } catch (IOException ex) {
                logger.warn("Error in FileWather", ex);
            }
    }
}
