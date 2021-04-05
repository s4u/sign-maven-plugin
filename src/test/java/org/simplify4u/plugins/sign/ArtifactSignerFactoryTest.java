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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.apache.maven.rtinfo.RuntimeInformation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.simplify4u.plugins.sign.openpgp.PGPKeyInfo;

@ExtendWith(MockitoExtension.class)
class ArtifactSignerFactoryTest {

    @Mock
    private PGPKeyInfo keyInfo;

    @Mock
    private ArtifactSigner36 artifactSigner36;

    @Mock
    private ArtifactSigner40 artifactSigner40;

    @Mock
    private RuntimeInformation rtInfo;

    @InjectMocks
    ArtifactSignerFactory artifactSignerFactory;

    @Test
    void maven36() {
        // given
        when(rtInfo.isMavenVersion("[4.0.0-alpha-0,)")).thenReturn(false);

        // whwn
        ArtifactSigner signer = artifactSignerFactory.getSigner(keyInfo);

        // then
        assertThat(signer).isSameAs(artifactSigner36);
        verify(artifactSigner36).setKeyInfo(keyInfo);
        verifyNoInteractions(artifactSigner40);
    }

    @Test
    void maven40() {
        // given
        when(rtInfo.isMavenVersion("[4.0.0-alpha-0,)")).thenReturn(true);

        // whwn
        ArtifactSigner signer = artifactSignerFactory.getSigner(keyInfo);

        // then
        assertThat(signer).isSameAs(artifactSigner40);
        verify(artifactSigner40).setKeyInfo(keyInfo);
        verifyNoInteractions(artifactSigner36);
    }

}
