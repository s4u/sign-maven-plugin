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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.inject.Inject;
import javax.inject.Named;

import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.transform.FileTransformer;

/**
 * Artifact signer - implementation for Maven &gt;= 3.7.0
 *
 * @author Slawomir Jaranowski
 */
@Slf4j
@Named
public class ArtifactSigner40 extends ArtifactSigner {

    @Inject
    private MavenSession session;

    @Override
    public List<SignResult> signArtifact(Artifact artifact) {
        LOGGER.info("Signing artifact: {}", artifact);

        org.eclipse.aether.artifact.Artifact srcArtifact = new org.eclipse.aether.artifact.DefaultArtifact(
                artifact.getGroupId(),
                artifact.getArtifactId(),
                artifact.getClassifier(),
                artifact.getArtifactHandler().getExtension(),
                artifact.getVersion(),
                null,
                artifact.getFile());

        Collection<FileTransformer> transformersForArtifact = session.getRepositorySession().getFileTransformerManager()
                .getTransformersForArtifact(srcArtifact);

        List<SignResult> result = new ArrayList<>();

        try {
            if (transformersForArtifact.isEmpty()) {
                try (InputStream artifactInputStream = new BufferedInputStream(
                        Files.newInputStream(srcArtifact.getFile().toPath()))) {
                    result.add(makeSignature(artifactInputStream,
                            srcArtifact.getArtifactId(),
                            srcArtifact.getClassifier(),
                            srcArtifact.getExtension()));
                }
            } else {
                for (FileTransformer fileTransformer : transformersForArtifact) {
                    org.eclipse.aether.artifact.Artifact dstArtifact = fileTransformer.transformArtifact(srcArtifact);
                    result.add(makeSignature(fileTransformer.transformData(srcArtifact.getFile()),
                            dstArtifact.getArtifactId(),
                            dstArtifact.getClassifier(),
                            dstArtifact.getExtension()));
                }
            }
        } catch (IOException e) {
            throw new SignMojoException(e);
        }

        return result;
    }
}
