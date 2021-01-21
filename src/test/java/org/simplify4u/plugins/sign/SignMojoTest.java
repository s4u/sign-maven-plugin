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
package org.simplify4u.plugins.sign;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.simplify4u.plugins.sign.openpgp.PGPSignerKeyNotFoundException;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;

@ExtendWith(MockitoExtension.class)
class SignMojoTest {

    @Mock
    private MavenProject project;

    @Mock
    private ArtifactSigner artifactSigner;

    @Mock
    private ArtifactSignerFactory artifactSignerFactory;

    @Mock
    private SecDispatcher secDispatcher;

    @InjectMocks
    private SignMojo mojo;

    @Test
    void skipExecution() {

        //given
        mojo.setSkip(true);

        // when
        mojo.execute();

        // then
        verifyNoInteractions(artifactSignerFactory, artifactSigner, secDispatcher, project);
    }

    @Test
    void noExistingKeyShouldSkipExecution() {
        // given
        mojo.setSkipNoKey(true);
        mojo.setKeyFile(new File("no-existing-key.asc"));

        // when
        mojo.execute();

        //then
        verifyNoInteractions(artifactSignerFactory, artifactSigner, secDispatcher, project);
    }

    @Test
    void noExistingKeyShouldBreakExecution() {
        // given
        mojo.setSkipNoKey(false);
        mojo.setKeyFile(new File("no-existing-key.asc"));

        // when - then
        assertThatThrownBy(() -> mojo.execute())
                .isExactlyInstanceOf(PGPSignerKeyNotFoundException.class)
                .hasMessage("key file: no-existing-key.asc not found");

        verifyNoInteractions(artifactSignerFactory, artifactSigner, secDispatcher, project);
    }

    @Nested
    class ExecutionTesting {

        @BeforeEach
        void setup() {
            DefaultArtifact artifact = new DefaultArtifact("groupId", "artifactId", "1.0.0", null, "pom", null,
                    new DefaultArtifactHandler("pom"));
            when(project.getGroupId()).thenReturn(artifact.getGroupId());
            when(project.getArtifactId()).thenReturn(artifact.getArtifactId());
            when(project.getVersion()).thenReturn(artifact.getVersion());
            when(project.getArtifact()).thenReturn(artifact);

            when(artifactSignerFactory.getSigner(any())).thenReturn(artifactSigner);

            //setup default values of mojo
            mojo.setKeyFile(new File(getClass().getResource("/priv-key-no-pass.asc").getFile()));
        }

        @Test
        void executeWithOutParams() {

            mojo.execute();

            verify(artifactSigner).signArtifact(any());
            verifyNoInteractions(secDispatcher);
        }

        @Test
        void executeWithPassword() throws Exception {

            mojo.setKeyPass("keyPass");
            mojo.execute();

            verify(artifactSigner).signArtifact(any());
            verify(secDispatcher).decrypt("keyPass");
        }
    }

}
