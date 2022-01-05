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
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;
import org.slf4j.Logger;

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

    @Spy
    private Logger logger;

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
        when(project.getFile()).thenReturn(new File("pom.xml"));
        when(project.getBasedir()).thenReturn(new File("."));

        when(keyInfoFactory.buildKeyInfo(any())).thenReturn(PGPKeyInfo.builder().key(new byte[]{1, 2, 3}).build());

        when(artifactSignerFactory.getSigner(any())).thenReturn(artifactSigner);

        when(artifactSigner.signArtifact(any())).thenReturn(Collections.singletonList(SignResult.builder().build()));

        mojo.execute();

        verify(artifactSigner).signArtifact(artifact);
        verify(projectHelper).attachArtifact(eq(project), any(), any(), any());

        verifyNoMoreInteractions(artifactSigner, projectHelper);
    }

    @Test
    void excludeArtifact() {

        DefaultArtifact artifact = new DefaultArtifact("groupId", "artifactId", "1.0.0", null, "pom", null,
                new DefaultArtifactHandler("pom"));

        when(project.getGroupId()).thenReturn(artifact.getGroupId());
        when(project.getArtifactId()).thenReturn(artifact.getArtifactId());
        when(project.getVersion()).thenReturn(artifact.getVersion());
        when(project.getArtifact()).thenReturn(artifact);
        when(project.getFile()).thenReturn(new File("pom.xml"));
        when(project.getBasedir()).thenReturn(new File("."));

        Artifact artifactMd5 = aArtifactWithFile("artifact2", "pom.xml.md5");

        when(project.getAttachedArtifacts()).thenReturn(Collections.singletonList(artifactMd5));

        when(keyInfoFactory.buildKeyInfo(any())).thenReturn(PGPKeyInfo.builder().key(new byte[]{1, 2, 3}).build());

        when(artifactSignerFactory.getSigner(any())).thenReturn(artifactSigner);

        when(artifactSigner.signArtifact(any())).thenReturn(Collections.singletonList(SignResult.builder().build()));

        mojo.setExcludes(Collections.singletonList("**/*.md5"));
        mojo.execute();

        verify(artifactSigner).signArtifact(artifact);
        verify(projectHelper).attachArtifact(eq(project), any(), any(), any());

        verifyNoMoreInteractions(artifactSigner, projectHelper);
    }

    private Artifact aArtifactWithFile(String artifactId, String fileName) {
        DefaultArtifact artifact = new DefaultArtifact("groupId", artifactId, "1.0.0", null, "pom", null,
                new DefaultArtifactHandler("pom"));
        artifact.setFile(new File(fileName));
        return artifact;
    }

}


