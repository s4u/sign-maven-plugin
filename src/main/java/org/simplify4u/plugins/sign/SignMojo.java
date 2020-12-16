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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import javax.inject.Inject;

import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.apache.maven.project.artifact.ProjectArtifact;
import org.apache.maven.rtinfo.RuntimeInformation;
import org.eclipse.aether.transform.FileTransformer;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;
import org.simplify4u.plugins.sign.openpgp.PGPSigner;

/**
 * Creates OpenPGP signatures for all of the project's artifacts.
 *
 * @author Slawomir Jaranowski
 * @since 0.1.0
 */
@Slf4j
@Mojo(name = "sign", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SignMojo extends AbstractMojo {

    @Inject
    private MavenProject project;

    @Inject
    private MavenSession session;

    /**
     * <p><code>keyId</code> used for signing. If not provided first key from <code>keyFile</code> will be taken.</p>
     *
     * @since 0.1.0
     */
    @Parameter(property = "sign.keyId")
    private String keyId;

    /**
     * <p><code>passphrase</code> to decrypt private signing key.</p>
     *
     * <p>Provided key can be stored in plain text, in this case <code>keyPass</code> can be empty.</p>
     *
     * <p>This value can be delivered by environment variable <code>SIGN_KEY_PASS</code>.</p>
     *
     * @since 0.1.0
     */
    @Parameter(property = "sign.keyPass")
    private String keyPass;

    /**
     * <p>File with <code>private key</code> used for signing.</p>
     *
     * <p>This value can be delivered by environment variable <code>SIGN_KEY</code>.
     * Environment variable must contain private key content.</p>
     *
     * <p>Key can by created and exported by:</p>
     * <pre>
     *      gpg --armor --export-secret-keys
     * </pre>
     * <p>
     *
     * @since 0.1.0
     */
    @Parameter(property = "sign.keyFile", defaultValue = "${user.home}/.m2/sign-key.asc")
    private File keyFile;

    @Inject
    private MavenProjectHelper projectHelper;

    @Inject
    private RuntimeInformation rtInfo;

    @Inject
    private PGPSigner pgpSigner;


    @Override
    public void execute() {

        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyId(keyId)
                .keyPass(keyPass)
                .keyFile(keyFile)
                .build();

        pgpSigner.setKeyInfo(keyInfo);

        // collect artifact to sign
        Set<Artifact> artifactsToSign = new HashSet<>();

        artifactsToSign.add(new ProjectArtifact(project));
        artifactsToSign.add(project.getArtifact());
        artifactsToSign.addAll(project.getAttachedArtifacts());

        Function<Artifact, List<SignResult>> signMethod;

        if (rtInfo.isMavenVersion("[3.7.0,)")) {
            signMethod = this::signArtifact;
        } else {
            signMethod = this::signArtifact36;
        }

        // sign and attach signature to project
        artifactsToSign.stream()
                .filter(SignMojo::verifyArtifact)
                .map(signMethod)
                .flatMap(List::stream)
                .forEach(this::attachSignResult);
    }

    private static boolean verifyArtifact(Artifact artifact) {

        if (artifact == null) {
            throw new SignMojoException("null artifacts ...");
        }

        if (artifact.getFile() == null) {
            throw new SignMojoException("Artifact: " + artifact + " has no file");
        }

        return true;
    }

    private List<SignResult> signArtifact36(Artifact artifact) {

        try (InputStream artifactInputStream = new BufferedInputStream(new FileInputStream(artifact.getFile()))) {
            return Collections.singletonList(makeSignature(artifactInputStream,
                    artifact.getArtifactId(),
                    artifact.getClassifier(),
                    artifact.getArtifactHandler().getExtension()));
        } catch (IOException e) {
            throw new SignMojoException(e);
        }
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
    private List<SignResult> signArtifact(Artifact artifact) {
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
                        new FileInputStream(srcArtifact.getFile()))) {
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
    private SignResult makeSignature(InputStream inputStream, String artifactId, String classifier, String extension) {

        String targetExt = extension + ".asc";

        String targetName = artifactId;
        if (classifier != null && !classifier.isEmpty()) {
            targetName += "-" + classifier;
        }
        targetName += "." + targetExt;

        Path target = Paths.get(project.getBuild().getDirectory(), targetName);

        pgpSigner.sign(inputStream, target);

        return new SignResult(classifier, targetExt, target.toFile());
    }

    /**
     * Attache sign result to project.
     */
    private void attachSignResult(SignResult signResult) {
        LOGGER.info("Attach signature: {}", signResult);

        projectHelper
                .attachArtifact(project, signResult.getExtension(), signResult.getClassifier(), signResult.getFile());
    }
}
