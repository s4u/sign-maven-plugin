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
import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import java.util.function.UnaryOperator;

import io.vavr.control.Try;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

/**
 * Information about pgp key.
 *
 * @author Slawomir Jaranowski
 */

@Slf4j
@Getter
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class PGPKeyInfo {

    private static final String SIGN_KEY_ID_ENV = "SIGN_KEY_ID";
    private static final String SIGN_KEY_ENV = "SIGN_KEY";
    private static final String SIGN_KEY_PASS_ENV = "SIGN_KEY_PASS";

    Long id;
    char[] pass;
    InputStream key;

    @Builder
    private PGPKeyInfo(String keyId, String keyPass, File keyFile, UnaryOperator<String> passDecryptor) {

        id = Optional.ofNullable(stringFromEnv(SIGN_KEY_ID_ENV).orElse(keyId))
                .map(PGPKeyInfo::parseKeyId)
                .orElse(null);

        pass = Optional.ofNullable(stringFromEnv(SIGN_KEY_PASS_ENV).orElse(keyPass))
                .map(Optional.ofNullable(passDecryptor).orElseGet(UnaryOperator::identity))
                .map(String::toCharArray)
                .orElse(null);

        key = stringFromEnv(SIGN_KEY_ENV)
                .map(String::trim)
                .map(PGPKeyInfo::keyFromString)
                .orElseGet(() -> keyFromFile(keyFile));
    }

    /**
     * Read environment variable and filter by "null" string - this value is set be invoker-maven-plugin.
     * <p>
     * TODO - remove workaround after fix and release https://issues.apache.org/jira/browse/MINVOKER-273
     *
     * @param environmentName a environment variable name
     *
     * @return content of environment variable or empty if not exist.
     */
    private static Optional<String> stringFromEnv(String environmentName) {
        Optional<String> returnValue = Optional.ofNullable(System.getenv(environmentName))
                .map(String::trim)
                .filter(s -> !"null".equals(s))
                .filter(s -> !s.isEmpty());

        if (returnValue.isPresent()) {
            LOGGER.debug("Retrieved {} configuration from environment variable", environmentName);
        } else {
            LOGGER.debug("No {} set as environment variable", environmentName);
        }

        return returnValue;
    }

    private static InputStream keyFromFile(File keyFile) {

        if (!keyFile.exists()) {
            throw new PGPSignerKeyNotFoundException("key file: " + keyFile + " not found");
        }

        return Try.of(() -> Files.readAllBytes(keyFile.toPath()))
                .map(ByteArrayInputStream::new)
                .getOrElseThrow(PGPSignerException::new);
    }

    private static InputStream keyFromString(String key) {
        return new ByteArrayInputStream(key.getBytes(StandardCharsets.US_ASCII));
    }

    private static long parseKeyId(String key) {
        return Try.of(() -> new BigInteger(key, 16))
                .map(BigInteger::longValue)
                .getOrElseThrow(e -> new PGPSignerException("Invalid keyId: " + e.getMessage()));
    }
}
