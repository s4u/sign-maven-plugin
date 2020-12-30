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
import java.util.Optional;
import java.util.stream.StreamSupport;
import javax.inject.Named;

import static org.simplify4u.plugins.sign.openpgp.PGPSecretKeyUtils.getKeyId;
import static org.simplify4u.plugins.sign.openpgp.PGPSecretKeyUtils.getUserIDs;
import static org.simplify4u.plugins.sign.openpgp.PGPSecretKeyUtils.keyIdDescription;
import static org.simplify4u.plugins.sign.openpgp.PGPSecretKeyUtils.verifyKeyExpiration;

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
public class PGPSigner {

    private PGPKeyInfo pgpKeyInfo;

    private PGPSecretKey secretKey;
    private PGPPrivateKey pgpPrivateKey;
    private PGPSignatureSubpacketVector hashSubPackets;
    private PGPSecretKeyRing secretKeyRing;

    PGPSigner() {
        // empty one
    }

    /**
     * Setup key info which will be used for signing
     *
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
            LOGGER.info("Loaded {}, uids: {}",
                    keyIdDescription(secretKey, secretKeyRing),
                    getUserIDs(secretKey, secretKeyRing));
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
        Optional<PGPSecretKey> secretKeyOptional;
        if (keyId != null) {
            secretKeyOptional = Optional.ofNullable(pgpSecretKeyRingCollection.getSecretKey(keyId));
        } else {
            // retrieve first key with private key
            secretKeyOptional = StreamSupport.stream(pgpSecretKeyRingCollection.spliterator(), false)
                    .flatMap(k -> StreamSupport.stream(k.spliterator(), false))
                    .filter(key -> !key.isPrivateKeyEmpty())
                    .findFirst();
        }

        secretKey = secretKeyOptional.orElseThrow(() -> new PGPSignerException("Secret key not found"));

        secretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(secretKey.getKeyID());

        if (secretKey.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithmTags.NULL && pgpKeyInfo.getPass() != null) {
            LOGGER.warn("Plain secret key - password is not needed");
        }

        if (secretKey.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithmTags.NULL && pgpKeyInfo.getPass() == null) {
            throw new PGPSignerException("Secret key is encrypted - keyPass is required");
        }

        if (secretKey.isPrivateKeyEmpty()) {
            throw new PGPSignerException("Private key not found for keyId: " + getKeyId(secretKey));
        }

        verifyKeyExpiration(secretKey, secretKeyRing);

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
                new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512));

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
