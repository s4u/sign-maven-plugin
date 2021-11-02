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
package org.simplify4u.plugins.sign;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import io.vavr.control.Try;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;
import org.simplify4u.plugins.sign.utils.Environment;
import org.simplify4u.plugins.sign.utils.FileUtil;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;

/**
 * Service to build {@link PGPKeyInfo} object.
 */
@Singleton
@Named
@Slf4j
public class KeyInfoFactory {

    private static final String SIGN_KEY_ID_ENV = "SIGN_KEY_ID";
    private static final String SIGN_KEY_ENV = "SIGN_KEY";
    private static final String SIGN_KEY_PASS_ENV = "SIGN_KEY_PASS";

    @Inject
    private Environment environment;

    @Inject
    private SecDispatcher secDispatcher;

    /**
     * Value class for data needed to build key info.
     */
    @Value
    @Builder
    public static class KeyInfoRequest {
        String id;
        String pass;
        File file;
    }

    /**
     * Build {@link PGPKeyInfo}.
     *
     * @param keyInfoRequest input data for key
     *
     * @return a {@link PGPKeyInfo} with resolved data.
     */
    public PGPKeyInfo buildKeyInfo(KeyInfoRequest keyInfoRequest) {

        return PGPKeyInfo.builder()
                .id(resolveKeyId(keyInfoRequest))
                .pass(resolveKeyPass(keyInfoRequest))
                .key(resolveKey(keyInfoRequest))
                .build();
    }

    private Long resolveKeyId(KeyInfoRequest keyInfoRequest) {
        return Optional.ofNullable(environment.getEnv(SIGN_KEY_ID_ENV).orElseGet(keyInfoRequest::getId))
                .map(KeyInfoFactory::parseKeyId)
                .orElse(null);
    }

    private String resolveKeyPass(KeyInfoRequest keyInfoRequest) {
        return Optional.ofNullable(environment.getEnv(SIGN_KEY_PASS_ENV).orElseGet(keyInfoRequest::getPass))
                .map(this::decryptPass)
                .orElse(null);
    }

    private byte[] resolveKey(KeyInfoRequest keyInfoRequest) {
        return environment.getEnv(SIGN_KEY_ENV)
                .map(String::trim)
                .map(KeyInfoFactory::keyFromString)
                .orElseGet(() -> keyFromFile(keyInfoRequest.getFile()));
    }

    private String decryptPass(String pass) {
        return Try.of(() -> secDispatcher.decrypt(pass))
                .getOrElseThrow(e -> new SignMojoException("Invalid encrypted password: " + e.getMessage()));
    }

    private static long parseKeyId(String key) {
        return Try.of(() -> new BigInteger(key, 16))
                .map(BigInteger::longValue)
                .getOrElseThrow(e -> new SignMojoException("Invalid keyId: " + e.getMessage()));
    }

    private static byte[] keyFromString(String key) {
        return key.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] keyFromFile(File keyFile) {

        File file = FileUtil.calculateWithUserHome(keyFile);

        if (file.exists()) {
            LOGGER.debug("Read key from file: {}", file);
            return Try.of(() -> Files.readAllBytes(file.toPath())).get();
        } else {
            LOGGER.debug("Key file: {} not exist", keyFile);
        }

        return new byte[]{};
    }
}
