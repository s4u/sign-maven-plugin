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
     * Check if artifact has correct data.
     * @param artifact an artifact to sign
     */
    protected static void verifyArtifact(Artifact artifact) {

        if (artifact == null) {
            throw new SignMojoException("null artifacts ...");
        }

        if (artifact.getFile() == null) {
            throw new SignMojoException("Artifact: " + artifact + " has no file");
        }
    }

    /**
     * Sign given input stream. In result we will have file with signature.
     *
     * @param inputStream data to sign
     * @param artifactId  used for build filename
     * @param classifier  used for build filename
     * @param extension   used for build filename
     *
     * @return result of signing
     */
    protected SignResult makeSignature(InputStream inputStream,
            String artifactId, String classifier, String version,
            String extension) {

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
