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

import org.elasticsearch.common.SuppressForbidden;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;

import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

@SuppressForbidden(
        reason = "Need to do file watching"
)
public class FileWatcher implements Runnable{
    private final String _roleMappingFilePath;
    private final RoleMapper _roleMapper;
    private final Logger logger;

    public FileWatcher(String roleMappingFilePath, RoleMapper roleMapper, Logger esLogger){
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
