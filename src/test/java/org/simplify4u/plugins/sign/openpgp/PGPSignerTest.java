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
package org.simplify4u.plugins.sign.openpgp;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

class PGPSignerTest {

    private PGPSigner pgpSigner = new PGPSigner();

    @Test
    void loadKeyWithAllProperties() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyId("AC71B3E31C0C0D38")
                .keyPass("testPass")
                .keyFile(new File(getClass().getResource("/pgp-priv-key.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void loadDefaultKey() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyPass("testPass")
                .keyFile(new File(getClass().getResource("/pgp-priv-key.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void loadDefaultKeyWithOutPass() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(new File(getClass().getResource("/pgp-priv-key-no-pass.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void keyWithOutPassButPassGiven() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyPass("testPass")
                .keyFile(new File(getClass().getResource("/pgp-priv-key-no-pass.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void requireNullPassThrowException() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(new File(getClass().getResource("/pgp-priv-key.asc").getFile()))
                .build();


        // when
        assertThatThrownBy(() -> pgpSigner.setKeyInfo(keyInfo))
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasNoCause()
                .hasMessage("Secret key is encrypted - keyPass is required");
    }

    @Test
    void requireInvalidPassThrowException() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyPass("xxx")
                .keyFile(new File(getClass().getResource("/pgp-priv-key.asc").getFile()))
                .build();


        // when
        assertThatThrownBy(() -> pgpSigner.setKeyInfo(keyInfo))
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasRootCauseExactlyInstanceOf(PGPException.class)
                .hasMessage("org.bouncycastle.openpgp.PGPException: checksum mismatch at 0 of 20");
    }

}
