/*
 * Copyright 2021 Slawomir Jaranowski
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.simplify4u.plugins.sign.utils;

import java.io.File;

import lombok.experimental.UtilityClass;

/**
 * Utility to manipulate key file name.
 */
@UtilityClass
public class FileUtil {

    private static final String USER_HOME_PREFIX = "~" + File.separator;

    /**
     * Replace ~/ by user home directory.
     *
     * @param keyFile a file to calculate
     *
     * @return file name with user hom directory
     */
    public File calculateWithUserHome(File keyFile) {

        String filePath = keyFile.getPath();

        if (filePath.startsWith(USER_HOME_PREFIX)) {
            return new File(System.getProperty("user.home"), filePath.substring(2));
        }

        return keyFile;
    }
}
