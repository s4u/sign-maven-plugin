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
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.simplify4u.plugins.sign.KeyInfoFactory.KeyInfoRequest;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;
import org.simplify4u.plugins.sign.utils.Environment;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

@ExtendWith(MockitoExtension.class)
class KeyInfoFactoryTest {

    private static final String KEY_ID_STR = "ABCDEF0123456789";
    private static final long KEY_ID = 0xABCDEF0123456789L;

    private static final String KEY_PASS_STR = "pass";
    private static final char[] KEY_PASS = KEY_PASS_STR.toCharArray();

    private static final File KEY_FILE = new File(PGPKeyInfo.class.getResource("/priv-key-no-pass.asc").getFile());

    @Mock
    private Environment environment;

    @Mock
    private SecDispatcher secDispatcher;

    @Mock
    private Settings settings;

    @Mock
    private MavenSession mavenSession;

    @InjectMocks
    private KeyInfoFactory keyInfoFactory;

    @BeforeEach
    void setup() throws SecDispatcherException {
        lenient().doAnswer(invocation -> invocation.getArgument(0))
                .when(secDispatcher).decrypt(Mockito.anyString());
    }

    @Test
    void keyFromFileAllPropertiesSet() throws IOException {

        // given
        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .id(KEY_ID_STR)
                .pass(KEY_PASS_STR)
                .file(KEY_FILE)
                .build();

        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(keyInfoRequest);

        // then
        assertThat(keyInfo.getId()).isEqualTo(KEY_ID);
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS);
        assertThat(keyInfo.getKey()).containsExactly(Files.readAllBytes(KEY_FILE.toPath()));
        assertThat(keyInfo.isKeyAvailable()).isTrue();
    }

    @Test
    void keyFromFileWithServerId() throws IOException {

        // given
        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .serverId("serverId")
                .id("aaa")
                .pass("bbb")
                .file(new File("fff"))
                .build();

        Server server = new Server();
        server.setUsername(KEY_ID_STR);
        server.setPassphrase(KEY_PASS_STR);
        server.setPrivateKey(KEY_FILE.getAbsolutePath());

        when(mavenSession.getSettings()).thenReturn(settings);
        when(settings.getServer("serverId")).thenReturn(server);

        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(keyInfoRequest);

        // then
        assertThat(keyInfo.getId()).isEqualTo(KEY_ID);
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS);
        assertThat(keyInfo.getKey()).containsExactly(Files.readAllBytes(KEY_FILE.toPath()));
        assertThat(keyInfo.isKeyAvailable()).isTrue();
    }

    @Test
    void keyFromFile() throws IOException {

        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .file(KEY_FILE)
                .build();

        // when
        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(keyInfoRequest);

        // then
        assertThat(keyInfo.getId()).isNull();
        assertThat(keyInfo.getPass()).isNull();
        assertThat(keyInfo.getKey()).containsExactly(Files.readAllBytes(KEY_FILE.toPath()));
        assertThat(keyInfo.isKeyAvailable()).isTrue();
    }

    @Test
    void keyDataFromEnv() {

        // given
        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .id("aaa")
                .pass("bbb")
                .file(new File("fff"))
                .build();

        mockEnvValue("SIGN_KEY", "signKey from environment");
        mockEnvValue("SIGN_KEY_ID", KEY_ID_STR);
        mockEnvValue("SIGN_KEY_PASS", KEY_PASS_STR);


        // when
        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(keyInfoRequest);

        // then
        assertThat(keyInfo.getId()).isEqualTo(KEY_ID);
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS);
        assertThat(keyInfo.getKey()).containsExactly("signKey from environment".getBytes());
        assertThat(keyInfo.isKeyAvailable()).isTrue();
    }

    @Test
    void keyDataFromEnvWithServerId() {

        // given
        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .serverId("serverId")
                .build();

        mockEnvValue("SIGN_KEY", "signKey from environment");
        mockEnvValue("SIGN_KEY_ID", KEY_ID_STR);
        mockEnvValue("SIGN_KEY_PASS", KEY_PASS_STR);

        Server server = new Server();
        server.setUsername("xxx");
        server.setPassphrase("ppp");
        server.setPrivateKey("kkk");

        when(mavenSession.getSettings()).thenReturn(settings);
        when(settings.getServer("serverId")).thenReturn(server);

        // when
        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(keyInfoRequest);

        // then
        assertThat(keyInfo.getId()).isEqualTo(KEY_ID);
        assertThat(keyInfo.getPass()).isEqualTo(KEY_PASS);
        assertThat(keyInfo.getKey()).containsExactly("signKey from environment".getBytes());
        assertThat(keyInfo.isKeyAvailable()).isTrue();
    }


    @Test
    void invalidKeyIdThrowException() {

        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .id("xxx")
                .build();

        assertThatThrownBy(() -> keyInfoFactory.buildKeyInfo(keyInfoRequest))
                .isExactlyInstanceOf(SignMojoException.class)
                .hasMessageStartingWith("Invalid keyId: For input string: \"xxx\"")
                .hasNoCause();
    }

    @Test
    void notExistingKeyShouldReturnEmptyKey() {

        KeyInfoRequest keyInfoRequest = KeyInfoRequest.builder()
                .file(new File("xxx/xxx.asc"))
                .build();

        // when
        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(keyInfoRequest);

        // then
        assertThat(keyInfo.getKey()).isEmpty();
        assertThat(keyInfo.isKeyAvailable()).isFalse();
    }

    private void mockEnvValue(String key, String value) {
        when(environment.getEnv(key)).thenReturn(Optional.of(value));
    }
}
