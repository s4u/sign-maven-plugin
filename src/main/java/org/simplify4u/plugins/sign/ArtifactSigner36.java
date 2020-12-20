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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import javax.inject.Named;

import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;

/**
 * Artifact signer - implementation for Maven &gt;= 3.6.x and &lt;3.7.0
 *
 * @author Slawomir Jaranowski
 */
@Slf4j
@Named
public class ArtifactSigner36 extends ArtifactSigner {

    @Override
    public List<SignResult> signArtifact(Artifact artifact) {
        LOGGER.info("Signing artifact: {}", artifact);

        verifyArtifact(artifact);

        try (InputStream artifactInputStream = new BufferedInputStream(new FileInputStream(artifact.getFile()))) {
            return Collections.singletonList(makeSignature(artifactInputStream,
                    artifact.getArtifactId(),
                    artifact.getClassifier(),
                    artifact.getArtifactHandler().getExtension()));
        } catch (IOException e) {
            throw new SignMojoException(e);
        }
    }
}
