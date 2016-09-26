/**
 * JOSEPH - JavaScript Object Signing and Encryption Pentesting Helper
 * Copyright (C) 2016 Dennis Detering
 * <p>
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * <p>
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package eu.dety.burp.joseph.utilities;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;

/**
 * Help functions to perform cryptographic operations.
 * @author Dennis Detering
 * @version 1.0
 */
public class Crypto {
    public static final List<String> JWS_HMAC_ALGS = Arrays.asList("HS256", "HS384", "HS512");

    /**
     * Get MAC algorithm name for Java by JOSE algorithm name
     * @param algorithm Algorithm name as string
     * @param fallback Fallback return value if none of the defined match
     * @return MAC algorithm name as used by Java
     */
    public static String getMacAlgorithmByJoseAlgorithm(String algorithm, String fallback) {
        switch (algorithm) {
            case "HS256":
                return "HmacSHA256";
            case "HS384":
                return "HmacSHA384";
            case "HS512":
                return "HmacSHA512";
            default:
                return fallback;
        }
    }

    /**
     * Get key length needed for JOSE operation by JOSE algorithm name
     * @param algorithm Algorithm name as string
     * @param fallback Fallback return value if none of the defined match
     * @return Key length for JOSE operation
     */
    public static int getJoseKeyLengthByJoseAlgorithm(String algorithm, int fallback) {
        switch (algorithm) {
            case "A128GCM":
                return 16;
            case "A192GCM":
                return 24;
            case "A128CBC-HS256":
            case "A256GCM":
                return 32;
            case "A192CBC-HS384":
                return 48;
            case "A256CBC-HS512":
                return 64;
            default:
                return fallback;
        }
    }

    /**
     * Get key length needed for AES operation by JOSE algorithm name
     * @param algorithm Algorithm name as string
     * @param fallback Fallback return value if none of the defined match
     * @return Key length for AES operation
     */
    public static int getAesKeyLengthByJoseAlgorithm(String algorithm, int fallback) {
        switch (algorithm) {
            case "A128GCM":
            case "A128CBC-HS256":
                return 16;
            case "A192GCM":
            case "A192CBC-HS384":
                return 24;
            case "A256GCM":
            case "A256CBC-HS512":
                return 32;
            default:
                return fallback;
        }
    }

    /**
     * Generate MAC
     * @param algorithm Algorithm name as string
     * @param key Symmetric key as byte array
     * @param message Input message as byte array
     * @return Key length for JOSE operation
     */
    public static byte[] generateMac(String algorithm, byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            SecretKeySpec secret_key = new SecretKeySpec(key, algorithm);
            mac.init(secret_key);

            return mac.doFinal(message);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypt AES ciphertext
     * @param header JOSE header
     * @param key Symmetric key as byte array
     * @param iv Initialization Vector as byte array
     * @param cipherBytes Ciphertext as byte array
     * @param authTag Authentication tag as byte array
     * @throws DecryptionFailedException
     * @return Decrypted message as byte array
     */
    public static byte[] decryptAES(String header, byte[] key, byte[] iv, byte[] cipherBytes, byte[] authTag) throws DecryptionFailedException {
        byte[] decryptedContent;

        String encAlg = Decoder.getValueByBase64String(header, "enc").toUpperCase();

        int keyLen = getAesKeyLengthByJoseAlgorithm(encAlg, 32);
        String cipherInstance;

        switch (encAlg) {
            case "A128CBC-HS256":
                cipherInstance = "AES/CBC/PKCS5Padding";
                break;
            case "A192CBC-HS384":
                cipherInstance = "AES/CBC/PKCS5Padding";
                break;
            case "A256CBC-HS512":
                cipherInstance = "AES/CBC/PKCS5Padding";
                break;
            case "A128GCM":
                cipherInstance = "AES/GCM/NoPadding";
                break;
            case "A192GCM":
                cipherInstance = "AES/GCM/NoPadding";
                break;
            case "A256GCM":
                cipherInstance = "AES/GCM/NoPadding";
                break;
            default:
                throw new DecryptionFailedException("Could not determine encryption algorithm or it is not supported");
        }


        byte[] keyBytes = Arrays.copyOfRange(key, key.length - keyLen, key.length);

        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher;

        try {
            // Change isRestricted value of JceSecurity to allow AES key length > 128
            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);
            field.set(null, java.lang.Boolean.FALSE);

            cipher = Cipher.getInstance(cipherInstance, new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));

            if (encAlg.contains("GCM")) {
                cipher.updateAAD(header.getBytes());

                // Concatenate ciphertext and authentication tag byte arrays
                byte[] concat = new byte[cipherBytes.length + authTag.length];
                System.arraycopy(cipherBytes, 0, concat, 0, cipherBytes.length);
                System.arraycopy(authTag, 0, concat, cipherBytes.length, authTag.length);

                decryptedContent = cipher.doFinal(concat);
            } else {
                decryptedContent = cipher.doFinal(cipherBytes);
            }

        } catch (Exception e) {
            throw new DecryptionFailedException(e.getMessage());
        }

        return decryptedContent;

    }
}
