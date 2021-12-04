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

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;

@ExtendWith(MockitoExtension.class)
class SignMojoTest {

    @Mock
    private MavenProject project;

    @Mock
    private MavenProjectHelper projectHelper;

    @Mock
    private ArtifactSigner artifactSigner;

    @Mock
    private ArtifactSignerFactory artifactSignerFactory;

    @Mock
    private KeyInfoFactory keyInfoFactory;

    @InjectMocks
    private SignMojo mojo;

    @Test
    void skipExecution() {

        //given
        mojo.setSkip(true);

        // when
        mojo.execute();

        // then
        verifyNoInteractions(artifactSignerFactory, artifactSigner, keyInfoFactory, project);
    }

    @Test
    void emptyKeyInfoShouldSkipExecution() {
        // given
        mojo.setSkipNoKey(true);
        when(keyInfoFactory.buildKeyInfo(any())).thenReturn(PGPKeyInfo.builder().build());

        // when
        mojo.execute();

        //then
        verifyNoInteractions(artifactSignerFactory, artifactSigner, project);
    }

    @Test
    void emptyKeyInfoShouldBreakExecution() {
        // given
        mojo.setSkipNoKey(false);
        when(keyInfoFactory.buildKeyInfo(any())).thenReturn(PGPKeyInfo.builder().build());

        // when - then
        assertThatThrownBy(() -> mojo.execute())
                .isExactlyInstanceOf(SignMojoException.class)
                .hasMessage("Required key for signing not found");

        verifyNoInteractions(artifactSignerFactory, artifactSigner, project);
    }

    @Test
    void standardFlow() {

        DefaultArtifact artifact = new DefaultArtifact("groupId", "artifactId", "1.0.0", null, "pom", null,
                new DefaultArtifactHandler("pom"));
        when(project.getGroupId()).thenReturn(artifact.getGroupId());
        when(project.getArtifactId()).thenReturn(artifact.getArtifactId());
        when(project.getVersion()).thenReturn(artifact.getVersion());
        when(project.getArtifact()).thenReturn(artifact);

        when(keyInfoFactory.buildKeyInfo(any())).thenReturn(PGPKeyInfo.builder().key(new byte[]{1, 2, 3}).build());

        when(artifactSignerFactory.getSigner(any())).thenReturn(artifactSigner);

        when(artifactSigner.signArtifact(any())).thenReturn(Collections.singletonList(SignResult.builder().build()));

        mojo.execute();

        verify(artifactSigner).signArtifact(any());
        verify(projectHelper).attachArtifact(eq(project), any(), any(), any());
    }

}


