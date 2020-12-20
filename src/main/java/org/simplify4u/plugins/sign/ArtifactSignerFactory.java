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

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.maven.rtinfo.RuntimeInformation;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;

/**
 * Return ArtifactSigner depends on Maven version.
 *
 * @author Slawomir Jaranowski
 */
@Named
public class ArtifactSignerFactory {

    @Inject
    private ArtifactSigner36 artifactSigner36;

    @Inject
    private ArtifactSigner40 artifactSigner40;

    @Inject
    private RuntimeInformation rtInfo;

    /**
     * Detect Maven version and return proper signer instance.
     *
     * @param pgpKeyInfo a private key configuration
     *
     * @return ArtifactSigner for current maven version
     */
    public ArtifactSigner getSigner(PGPKeyInfo pgpKeyInfo) {

        ArtifactSigner artifactSigner;
        if (rtInfo.isMavenVersion("[3.7.0,)")) {
            artifactSigner = artifactSigner40;
        } else {
            artifactSigner = artifactSigner36;
        }

        artifactSigner.setKeyInfo(pgpKeyInfo);
        return artifactSigner;
    }
}
