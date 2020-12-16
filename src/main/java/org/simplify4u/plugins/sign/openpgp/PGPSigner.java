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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.inject.Named;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * Signig data by PGP.
 *
 * @author Slawomir Jaranowski
 */
@Slf4j
@Named
public final class PGPSigner {

    private PGPKeyInfo pgpKeyInfo;

    private PGPSecretKey secretKey;
    private PGPPrivateKey pgpPrivateKey;
    private PGPSignatureSubpacketVector hashSubPackets;

    PGPSigner() {
        // empty one
    }

    /**
     * Setup key info which will be used for signing
     * @param keyInfo private key info
     */
    public void setKeyInfo(PGPKeyInfo keyInfo) {

        this.pgpKeyInfo = keyInfo;
        try {
            loadKey();
            prepareAdditionalSubPacket();
        } catch (IOException | PGPException e) {
            throw new PGPSignerException(e);
        }

        if (LOGGER.isInfoEnabled()) {
            List<String> uIds = new ArrayList<>();
            secretKey.getUserIDs().forEachRemaining(uIds::add);
            LOGGER.info("Loaded keyId: {}, uIds: {}", String.format("%16X", secretKey.getKeyID()), uIds);
        }
    }

    private void prepareAdditionalSubPacket() {
        PGPSignatureSubpacketGenerator subPacketGenerator = new PGPSignatureSubpacketGenerator();
        // PGP subpacket 33 - issuer key fingerprint
        subPacketGenerator.setIssuerFingerprint(false, secretKey);
        hashSubPackets = subPacketGenerator.generate();
    }

    /**
     * Find and load private key from file.
     */
    private void loadKey() throws IOException, PGPException {

        InputStream inputStream = PGPUtil.getDecoderStream(pgpKeyInfo.getKey());
        PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(inputStream,
                new JcaKeyFingerprintCalculator());

        Long keyId = pgpKeyInfo.getId();
        if (keyId != null) {
            secretKey = pgpSecretKeyRingCollection.getSecretKey(keyId);
        } else {
            // retrieve first master key
            Iterator<PGPSecretKeyRing> keyRings = pgpSecretKeyRingCollection.getKeyRings();
            if (keyRings.hasNext()) {
                PGPSecretKeyRing secretKeys = keyRings.next();
                secretKey = secretKeys.getSecretKey();
            }
        }

        if (secretKey == null) {
            throw new PGPSignerException("Secret key not found");
        }

        if (secretKey.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithmTags.NULL && pgpKeyInfo.getPass() != null) {
            LOGGER.warn("Plain secret key - password is not needed");
        }

        if (secretKey.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithmTags.NULL && pgpKeyInfo.getPass() == null) {
            throw new PGPSignerException("Secret key is encrypted - keyPass is required");
        }

        pgpPrivateKey = secretKey
                .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(pgpKeyInfo.getPass()));
    }

    /**
     * Generate PGP signature for a given input stream.
     *
     * @param inputStream stream with data to calculate signature
     * @param outputPath  a destination of signature
     *
     * @throws PGPSignerException if some IO problems
     */
    public void sign(InputStream inputStream, Path outputPath) {

        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256));

        try {
            sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);
            sGen.setHashedSubpackets(hashSubPackets);

            int len;
            byte[] buffer = new byte[8 * 1024];
            while ((len = inputStream.read(buffer)) >= 0) {
                sGen.update(buffer, 0, len);
            }

            Files.createDirectories(outputPath.getParent());

            try (OutputStream out = Files.newOutputStream(outputPath);
                 BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(new ArmoredOutputStream(out))) {
                sGen.generate().encode(bcpgOutputStream);
            }
        } catch (PGPException | IOException e) {
            throw new PGPSignerException(e);
        }
    }
}
