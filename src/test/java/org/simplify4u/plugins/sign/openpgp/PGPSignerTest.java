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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

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
                .keyFile(new File(getClass().getResource("/priv-key.asc").getFile()))
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
                .keyFile(new File(getClass().getResource("/priv-key.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void loadDefaultKeyWithOutPass() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(new File(getClass().getResource("/priv-key-no-pass.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void loadSubKeyWithOutPass() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(new File(getClass().getResource("/priv-sub-key-no-pass.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void loadSubKeyWithMasterKey() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyId("0C5CEA1C96038404")
                .keyFile(new File(getClass().getResource("/priv-sub-key-no-pass.asc").getFile()))
                .build();


        // when
        assertThatThrownBy(() -> pgpSigner.setKeyInfo(keyInfo))
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasMessage("Private key not found for keyId: 0x0C5CEA1C96038404");
    }

    @Test
    void keyWithOutPassButPassGiven() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyPass("testPass")
                .keyFile(new File(getClass().getResource("/priv-key-no-pass.asc").getFile()))
                .build();


        // when
        assertThatCode(() -> pgpSigner.setKeyInfo(keyInfo))
                .doesNotThrowAnyException();
    }

    @Test
    void requireNullPassThrowException() throws PGPSignerException {

        // given
        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyFile(new File(getClass().getResource("/priv-key.asc").getFile()))
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
                .keyFile(new File(getClass().getResource("/priv-key.asc").getFile()))
                .build();


        // when
        assertThatThrownBy(() -> pgpSigner.setKeyInfo(keyInfo))
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasRootCauseExactlyInstanceOf(PGPException.class)
                .hasMessage("org.bouncycastle.openpgp.PGPException: checksum mismatch at 0 of 20");
    }

    @Test
    void expiredMasterKeyThrewException() {

        // given
        LocalDateTime expiredDateTime = ZonedDateTime.of(2020, 12, 23, 7, 29, 20, 0, ZoneOffset.UTC)
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyId("B09391374A115DE2")
                .keyFile(new File(getClass().getResource("/priv-expired-key-no-pass.asc").getFile()))
                .build();

        assertThatThrownBy(() -> pgpSigner.setKeyInfo(keyInfo))
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasNoCause()
                .hasMessage("KeyId: 0xE82078BE6F6368CB593C47C5B09391374A115DE2 was expired at: " + expiredDateTime);
    }

    @Test
    void expiredSubKeyThrewException() {

        // given
        LocalDateTime expiredDateTime = ZonedDateTime.of(2020, 12, 23, 7, 30, 13, 0, ZoneOffset.UTC)
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        PGPKeyInfo keyInfo = PGPKeyInfo.builder()
                .keyId("44A920F7DCC8A31E")
                .keyFile(new File(getClass().getResource("/priv-expired-key-no-pass.asc").getFile()))
                .build();

        assertThatThrownBy(() -> pgpSigner.setKeyInfo(keyInfo))
                .isExactlyInstanceOf(PGPSignerException.class)
                .hasNoCause()
                .hasMessage("SubKeyId: 0x44A920F7DCC8A31E of 0xE82078BE6F6368CB593C47C5B09391374A115DE2 was expired at: "
                        + expiredDateTime);
    }

}
