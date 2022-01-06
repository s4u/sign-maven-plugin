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


import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import javax.inject.Inject;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;
import org.simplify4u.plugins.sign.openpgp.PGPSigner;

/**
 * Common implementation for signing artifacts.
 *
 * @author Slawomir Jaranowski
 */
public abstract class ArtifactSigner {

    /**
     * current Maven project
     */
    @Inject
    protected MavenProject project;

    /**
     * signer to produce pgp signature
     */
    @Inject
    protected PGPSigner pgpSigner;

    /**
     * Convert artifact from Maven to aether space.
     * @param artifact a input artifact
     * @return new aether artifact
     */
    protected org.eclipse.aether.artifact.Artifact mArtifactToAether(Artifact artifact) {
        return new org.eclipse.aether.artifact.DefaultArtifact(
                artifact.getGroupId(),
                artifact.getArtifactId(),
                artifact.getClassifier(),
                artifact.getArtifactHandler().getExtension(),
                artifact.getVersion(),
                null,
                artifact.getFile());
    }

    /**
     * Sign given input stream. In result we will have file with signature.
     *
     * @param artifact    used for built filename
     * @param inputStream data to sign
     *
     * @return result of signing
     */
    protected SignResult makeSignature(org.eclipse.aether.artifact.Artifact artifact, InputStream inputStream) {

        String artifactId = artifact.getArtifactId();
        String classifier = artifact.getClassifier();
        String version = artifact.getVersion();
        String extension = artifact.getExtension();

        String targetExt = extension + ".asc";
        String targetName = artifactId + '-' + version;

        if (classifier != null && !classifier.isEmpty()) {
            targetName += "-" + classifier;
        }

        targetName += "." + targetExt;

        Path target = Paths.get(project.getBuild().getDirectory(), targetName);

        pgpSigner.sign(inputStream, target);

        return new SignResult(classifier, targetExt, target.toFile());
    }

    /**
     * Setup signarer with key configuration
     *
     * @param pgpKeyInfo a private key configuration
     */
    public void setKeyInfo(PGPKeyInfo pgpKeyInfo) {
        pgpSigner.setKeyInfo(pgpKeyInfo);
    }

    /**
     * Sign given artifact. In result we can have multiple signatures, transformers can produce multiple output for one
     * artifact.
     * <p>
     * This method ask transformers for inputStream for all artifact mutations, and sign each stream.
     *
     * @param artifact artifact to sign
     *
     * @return sign result
     */
    public abstract List<SignResult> signArtifact(Artifact artifact);
}
