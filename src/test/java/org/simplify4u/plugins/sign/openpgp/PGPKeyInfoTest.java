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

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetEnvironmentVariable;

@ExtendWith(MockitoExtension.class)
class PGPKeyInfoTest {

    private static final String KEY_ID_STR = "ABCDEF0123456789";
    private static final long KEY_ID = 0xABCDEF0123456789L;

    private static final String KEY_PASS_STR = "pass";
    private static final char[] KEY_PASS = KEY_PASS_STR.toCharArray();

    private static final File KEY_FILE = new File(PGPKeyInfo.class.getResource("/priv-key-no-pass.asc").getFile());

    @Mock(name = "org.simplify4u.plugins.sign.openpgp.PGPKeyInfo")
    Logger logger;

    @Test
    void keyFromFileAllPropertiesSet() throws IOException {
        // when
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyId(KEY_ID_STR)
                .keyPass(KEY_PASS_STR)
                .keyFile(KEY_FILE)
                .build();

        // then
        assertThat(keyInfo.getId()).isEqualTo(KEY_ID);
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS);
        assertThat(keyInfo.getKey()).hasSameContentAs(Files.newInputStream(KEY_FILE.toPath()));
        Mockito.verify(logger).debug("No {} set as environment variable", "SIGN_KEY_ID");
        Mockito.verify(logger).debug("No {} set as environment variable", "SIGN_KEY_PASS");
        Mockito.verify(logger).debug("No {} set as environment variable", "SIGN_KEY");
        Mockito.verifyNoMoreInteractions(logger);
    }


    @Test
    void keyFromFile() throws IOException {

        // when
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(KEY_FILE)
                .build();

        // then
        assertThat(keyInfo.getId()).isNull();
        assertThat(keyInfo.getPass()).isNull();
        assertThat(keyInfo.getKey()).hasSameContentAs(Files.newInputStream(KEY_FILE.toPath()));
    }

    @Test
    @SetEnvironmentVariable(key = "SIGN_KEY", value = "signKey from environment")
    @SetEnvironmentVariable(key = "SIGN_KEY_ID", value = KEY_ID_STR)
    @SetEnvironmentVariable(key = "SIGN_KEY_PASS", value = KEY_PASS_STR)
    void keyDataFromEnv() {

        // when
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .build();

        // then
        assertThat(keyInfo.getId()).isEqualTo(KEY_ID);
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS);
        assertThat(keyInfo.getKey()).hasContent("signKey from environment");
        Mockito.verify(logger).debug("Retrieved {} configuration from environment variable", "SIGN_KEY_ID");
        Mockito.verify(logger).debug("Retrieved {} configuration from environment variable", "SIGN_KEY_PASS");
        Mockito.verify(logger).debug("Retrieved {} configuration from environment variable", "SIGN_KEY");
        Mockito.verifyNoMoreInteractions(logger);
    }

    @Test
    @SetEnvironmentVariable(key = "SIGN_KEY", value = "signKey from environment")
    void keyFromEnvWithFile() {

        // when
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(KEY_FILE)
                .build();

        // then
        assertThat(keyInfo.getId()).isNull();
        assertThat(keyInfo.getPass()).isNull();
        assertThat(keyInfo.getKey()).hasContent("signKey from environment");
    }

    @Test
    void invalidKeyIdThrowException() {

        PGPKeyInfo.PGPKeyInfoBuilder keyInfoBuilder = PGPKeyInfo.builder()
                .keyId("xxx");

        assertThatThrownBy(keyInfoBuilder::build)
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasMessageStartingWith("Invalid keyId: For input string: \"xxx\"")
                .hasNoCause();
    }

    @Test
    @SetEnvironmentVariable(key = "SIGN_KEY", value = "signKey from environment")
    @SetEnvironmentVariable(key = "SIGN_KEY_ID", value = "null")
    void nullStringInEnvironmentValueShouldBeFiltered() {
        // when
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .build();

        // then
        assertThat(keyInfo.getId()).isNull();
        assertThat(keyInfo.getPass()).isNull();
        assertThat(keyInfo.getKey()).hasContent("signKey from environment");
    }

    @Test
    void passDecryptorShouldBeCalled() {

        // when
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .passDecryptor(String::toUpperCase)
                .keyPass(KEY_PASS_STR)
                .keyFile(KEY_FILE)
                .build();

        // then
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS_STR.toUpperCase().toCharArray());
    }
}
