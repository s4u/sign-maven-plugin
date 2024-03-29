/*
 * Copyright 2020 Slawomir Jaranowski
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
package org.simplify4u.plugins.sign.openpgp;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Optional;

import lombok.Builder;
import lombok.Value;

/**
 * Information about pgp key.
 *
 * @author Slawomir Jaranowski
 */

@Value
@Builder
public class PGPKeyInfo {

    Long id;
    String pass;
    byte[] key;

    /**
     * Check key.
     *
     * @return true if key is available
     */
    public boolean isKeyAvailable() {
        return key != null && key.length > 0;
    }

    /**
     * Key as stream.
     *
     * @return the {@link InputStream} with key content
     */
    public InputStream getKeyStream() {
        return new ByteArrayInputStream(key);
    }

    /**
     * Key pass.
     *
     * @return the pass
     */
    public char[] getPass() {
        return Optional.ofNullable(pass)
                .map(String::toCharArray)
                .orElse(null);
    }
}
