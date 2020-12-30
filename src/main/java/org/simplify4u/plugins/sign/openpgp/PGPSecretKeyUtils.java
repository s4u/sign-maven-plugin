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

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

/**
 * Utility for operation on Secret Keys.
 *
 * @author Slawomir Jaranowski
 */
public final class PGPSecretKeyUtils {

    private PGPSecretKeyUtils() {
    }

    /**
     * Generate keyId as hex string.
     *
     * @param secretKey a key to print id
     *
     * @return keyId in hex format
     */
    public static String getKeyId(PGPSecretKey secretKey) {
        return String.format("0x%016X", secretKey.getKeyID());
    }

    /**
     * List of user ids from secret key. If secret key is sub key list is taken from master key.
     *
     * @param secretKey     a secret key for user ids
     * @param secretKeyRing a keyRing of connected keys - need for sub key
     *
     * @return List user ids from key
     */
    public static Collection<String> getUserIDs(PGPSecretKey secretKey, PGPSecretKeyRing secretKeyRing) {
        // use getRawUserIDs and standard java String to transform byte array to utf8
        // because BC generate exception if there is some problem in decoding utf8
        // https://github.com/s4u/pgpverify-maven-plugin/issues/61
        Set<byte[]> ret = new LinkedHashSet<>();
        secretKey.getPublicKey().getRawUserIDs().forEachRemaining(ret::add);

        getMasterKey(secretKey, secretKeyRing).ifPresent(masterKey ->
                masterKey.getPublicKey().getRawUserIDs().forEachRemaining(ret::add)
        );

        return ret.stream()
                .map(b -> new String(b, StandardCharsets.UTF_8))
                .collect(Collectors.toSet());
    }

    /**
     * Generate string with key id description.
     *
     * @param secretKey     given key
     * @param secretKeyRing keys ring with master and sub keys
     *
     * @return string with key id description
     */
    public static String keyIdDescription(PGPSecretKey secretKey, PGPSecretKeyRing secretKeyRing) {

        Optional<PGPSecretKey> masterKey = getMasterKey(secretKey, secretKeyRing);

        if (masterKey.isPresent()) {
            return String.format("SubKeyId: 0x%016X of %s", secretKey.getKeyID(), fingerprint(masterKey.get()));
        } else {
            return "KeyId: " + fingerprint(secretKey);
        }
    }

    /**
     * Return master key for given sub public key.
     *
     * @param secretKey     given key
     * @param secretKeyRing keys ring with master and sub keys
     *
     * @return master key of empty if not found or given key is master key
     */
    @SuppressWarnings("unchecked")
    public static Optional<PGPSecretKey> getMasterKey(PGPSecretKey secretKey, PGPSecretKeyRing secretKeyRing) {

        if (secretKey.isMasterKey()) {
            return Optional.empty();
        }

        Iterable<PGPSignature> signatures = () ->
                secretKey.getPublicKey().getSignaturesOfType(PGPSignature.SUBKEY_BINDING);

        return StreamSupport.stream(signatures.spliterator(), false)
                .map(s -> secretKeyRing.getSecretKey(s.getKeyID()))
                .findFirst();
    }

    /**
     * Generate string version of key fingerprint
     *
     * @param secretKey given key
     *
     * @return fingerprint as string
     */
    public static String fingerprint(PGPSecretKey secretKey) {
        return fingerprintToString(secretKey.getPublicKey().getFingerprint());
    }

    private static String fingerprintToString(byte[] bytes) {
        StringBuilder ret = new StringBuilder();
        ret.append("0x");
        for (byte b : bytes) {
            ret.append(String.format("%02X", b));
        }
        return ret.toString();
    }

    /**
     * Verify expiration time of secret key.
     *
     * @param secretKey     a key to check
     * @param secretKeyRing a keyRing used for prepare message
     *
     * @throws PGPSignerException if key expired
     */
    public static void verifyKeyExpiration(PGPSecretKey secretKey, PGPSecretKeyRing secretKeyRing) {

        long validSeconds = secretKey.getPublicKey().getValidSeconds();
        if (validSeconds > 0) {

            LocalDateTime expireDateTime = secretKey.getPublicKey().getCreationTime()
                    .toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime()
                    .plusSeconds(validSeconds);

            if (LocalDateTime.now().isAfter(expireDateTime)) {
                throw new PGPSignerException(keyIdDescription(secretKey, secretKeyRing)
                        + " was expired at: " + expireDateTime);
            }
        }
    }
}
