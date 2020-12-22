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

import io.vavr.control.Try;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.experimental.FieldDefaults;

/**
 * Information about pgp key.
 *
 * @author Slawomir Jaranowski
 */

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
    private PGPKeyInfo(String keyId, String keyPass, File keyFile) {

        id = Optional.ofNullable(Optional.ofNullable(System.getenv(SIGN_KEY_ID_ENV)).orElse(keyId))
                .map(PGPKeyInfo::parseKeyId)
                .orElse(null);

        pass = Optional.ofNullable(Optional.ofNullable(System.getenv(SIGN_KEY_PASS_ENV)).orElse(keyPass))
                .map(String::toCharArray)
                .orElse(null);

        key = Optional.ofNullable(System.getenv(SIGN_KEY_ENV))
                .map(String::trim)
                .map(PGPKeyInfo::keyFromString)
                .orElseGet(() -> keyFromFile(keyFile));
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
