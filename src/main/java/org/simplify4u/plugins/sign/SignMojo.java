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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;

import lombok.AccessLevel;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.apache.maven.project.artifact.ProjectArtifact;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;
import org.simplify4u.plugins.sign.openpgp.PGPSignerKeyNotFoundException;

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
    private MavenProjectHelper projectHelper;

    @Inject
    private ArtifactSignerFactory artifactSignerFactory;

    /**
     * <p><code>keyId</code> used for signing. If not provided first key from <code>keyFile</code> will be taken.</p>
     *
     * <p>This value can be delivered by environment variable <code>SIGN_KEY_ID</code>.</p>
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
    @Setter(AccessLevel.PACKAGE)
    @Parameter(property = "sign.keyFile", defaultValue = "${user.home}/.m2/sign-key.asc")
    private File keyFile;

    /**
     * Skip the execution of plugin.
     *
     * @since 0.1.0
     */
    @Setter(AccessLevel.PACKAGE)
    @Parameter(property = "sign.skip", defaultValue = "false")
    private boolean skip;

    /**
     * Skip the execution of plugin if private key is missing.
     * <p>
     * In other case error will be reported for current Maven session.
     *
     * @since 0.1.0
     */
    @Setter(AccessLevel.PACKAGE)
    @Parameter(property = "sign.skipNoKey", defaultValue = "false")
    private boolean skipNoKey;

    @Override
    public void execute() {

        if (skip) {
            LOGGER.info("Sign - skip execution");
            return;
        }

        PGPKeyInfo keyInfo;
        try {
            keyInfo = PGPKeyInfo.builder()
                    .keyId(keyId)
                    .keyPass(keyPass)
                    .keyFile(keyFile)
                    .build();
        } catch (PGPSignerKeyNotFoundException e) {
            if (skipNoKey) {
                LOGGER.info("Sign - key not found - skip execution");
                return;
            } else {
                throw e;
            }
        }

        ArtifactSigner artifactSigner = artifactSignerFactory.getSigner(keyInfo);

        // collect artifact to sign
        Set<Artifact> artifactsToSign = new HashSet<>();

        artifactsToSign.add(new ProjectArtifact(project));
        artifactsToSign.add(project.getArtifact());
        artifactsToSign.addAll(project.getAttachedArtifacts());

        // sign and attach signature to project
        artifactsToSign.stream()
                .map(artifactSigner::signArtifact)
                .flatMap(List::stream)
                .forEach(this::attachSignResult);
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
