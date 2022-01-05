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
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
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
import org.codehaus.plexus.util.SelectorUtils;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;

/**
 * Creates Open PGP / GPG signatures for all of the project's artifacts.
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
    private KeyInfoFactory keyInfoFactory;

    @Inject
    private ArtifactSignerFactory artifactSignerFactory;

    /**
     * <p>A <code>serverId</code> from settings.xml which contains configuration for private key used to signing.</p>
     *
     * <p><dl>
     * <dt>server.username</dt>
     * <dd>key id - optional value</dd>
     *
     * <dt>server.privateKey</dt>
     * <dd>path to file contains private key</dd>
     *
     * <dt>server.passphrase</dt>
     * <dd>password for decrypting private key</dd>
     * </dl></p>
     *
     * <p>
     * <b>NOTICE</b> when used <code>serverId</code> data from property
     * <code>keyId</code>, <code>keyPass</code> and <code>keyFile</code> will not be used.
     * </p>
     *
     * <p>
     * <b>Environment variable</b> - <code>SIGN_KEY_ID</code>, <code>SIGN_KEY_PASS</code> and <code>SIGN_KEY</code>
     * have always priority and when will be provided will be used <b>first</b>.
     * </p>
     *
     * @since 1.0.0
     */
    @Parameter(property = "sign.serverId")
    private String serverId;

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
     * <p>Can be encrypted by standard Maven
     * <a href="https://maven.apache.org/guides/mini/guide-encryption.html">Password Encryption</a></p>
     *
     * <p>Provided key can be stored in plain text, in this case <code>keyPass</code> can be empty.</p>
     *
     * <p>This value can be delivered by environment variable <code>SIGN_KEY_PASS</code>.</p>
     *
     * @since 0.1.0
     */
    @Setter(AccessLevel.PACKAGE)
    @Parameter(property = "sign.keyPass")
    private String keyPass;

    /**
     * <p>File with <code>private key</code> used for signing.</p>
     *
     * <p>This value can be delivered by environment variable <code>SIGN_KEY</code>.
     * Environment variable must contain private key content - not file path for key.</p>
     *
     * <p>If <code>keyFile</code> path start with <code>~/</code>
     * then <code>~/</code> will be replace by user home directory - java <code>user.home</code> property</p>
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
     * By default execution is skipped if private key is missing.
     * <p>
     * When set to <code>false</code> and private key is missing error will be reported for current Maven session.
     *
     * @since 0.1.0
     */
    @Setter(AccessLevel.PACKAGE)
    @Parameter(property = "sign.skipNoKey", defaultValue = "true")
    private boolean skipNoKey;

    /**
     * A list of files to exclude from being signed. Can contain Ant-style wildcards and double wildcards.
     *
     * @since 1.0.0
     */
    @Parameter(defaultValue = "**/*.md5,**/*.sha1,**/*.sha256,**/*.sha512,**/*.asc")
    private List<String> excludes = Collections.emptyList();

    /**
     * Set excludes list.
     *
     * @param excludes a list from plugin configuration
     */
    public void setExcludes(List<String> excludes) {

        String from = File.separatorChar == '/' ? "\\\\" : "/";

        // normalize excludes for current file separator
        this.excludes = excludes.stream()
                .map(s -> s.replace(from, File.separator))
                .collect(Collectors.toList());
    }

    @Override
    public void execute() {

        if (skip) {
            LOGGER.info("Sign - skip execution");
            return;
        }

        PGPKeyInfo keyInfo = keyInfoFactory.buildKeyInfo(
                KeyInfoFactory.KeyInfoRequest.builder()
                        .serverId(serverId)
                        .id(keyId)
                        .pass(keyPass)
                        .file(keyFile)
                        .build());

        if (!keyInfo.isKeyAvailable()) {
            if (skipNoKey) {
                LOGGER.info("Sign - key not found - skip execution");
                return;
            }
            throw new SignMojoException("Required key for signing not found");
        }

        ArtifactSigner artifactSigner = artifactSignerFactory.getSigner(keyInfo);

        // collect artifact to sign
        Set<Artifact> artifactsToSign = new HashSet<>();

        artifactsToSign.add(new ProjectArtifact(project));
        artifactsToSign.add(project.getArtifact());
        artifactsToSign.addAll(project.getAttachedArtifacts());

        // sign and attach signature to project
        artifactsToSign.stream()
                .map(SignMojo::verifyArtifact)
                .filter(this::shouldBeSigned)
                .map(artifactSigner::signArtifact)
                .flatMap(List::stream)
                .forEach(this::attachSignResult);
    }

    /**
     * Check if artifact has correct data.
     *
     * @param artifact an artifact to check
     *
     * @return the same artifact if is acceptable
     */
    private static Artifact verifyArtifact(Artifact artifact) {

        if (artifact == null) {
            throw new SignMojoException("null artifacts ...");
        }

        if (artifact.getFile() == null) {
            throw new SignMojoException("Artifact: " + artifact + " has no file");
        }

        return artifact;
    }

    /**
     * Check if artifact should be signed.
     */
    private boolean shouldBeSigned(Artifact artifact) {

        final Path projectBasePath = project.getBasedir().toPath();
        final Path artifactPath = artifact.getFile().toPath();
        final String relativeArtifactPath = projectBasePath.relativize(artifactPath).toString();

        boolean shouldSign = excludes.stream()
                .noneMatch(exclude -> SelectorUtils.matchPath(exclude, relativeArtifactPath));

        LOGGER.debug("Artifact: {} with relativeArtifactPath: {} shouldSign: {} due to excludes: {}",
                artifact, relativeArtifactPath, shouldSign, excludes);

        return shouldSign;
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
