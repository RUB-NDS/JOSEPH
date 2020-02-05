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

import eu.dety.burp.joseph.attacks.invalid_curve.Point;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.BigIntegers;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.List;

/**
 * Help functions to perform cryptographic operations.
 *
 * @author Dennis Detering, Vincent Unsel
 * @version 1.1
 */
public class Crypto {
    public static final List<String> JWS_HMAC_ALGS = Arrays.asList("HS256", "HS384", "HS512");
    private static final Logger loggerInstance = Logger.getInstance();

    /**
     * Get MAC algorithm name for Java by JOSE algorithm name
     *
     * @param algorithm
     *            Algorithm name as string
     * @param fallback
     *            Fallback return value if none of the defined match
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
     *
     * @param algorithm
     *            Algorithm name as string
     * @param fallback
     *            Fallback return value if none of the defined match
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
     *
     * @param algorithm
     *            Algorithm name as string
     * @param fallback
     *            Fallback return value if none of the defined match
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
     * Get key length needed for AEAD operation by JOSE algorithm name
     *
     * @param algorithm
     *            Algorithm name as string
     * @param fallback
     *            Fallback return value if none of the defined match
     * @return Key length for AEAD operation
     */
    public static int getAeadKeyLengthByJoseAlgorithm(String algorithm, int fallback) {
        switch (algorithm) {
            case "A128GCM":
                return 16;
            case "A192GCM":
                return 24;
            case "A256GCM":
            case "A128CBC-HS256":
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
     * Get key length needed for AESKW operation by JOSE algorithm name
     *
     * @param algorithm
     *            Algorithm name as string
     * @param fallback
     *            Fallback return value if none of the defined match
     * @return Key length for AESKW operation
     */
    public static int getAesKwKeyLengthByJoseAlgorithm(String algorithm, int fallback) {
        switch (algorithm) {
            case "A128KW":
                return 16;
            case "A192KW":
                return 24;
            case "A256KW":
                return 32;
            default:
                return fallback;
        }
    }

    /**
     * Get key length needed for ECDH-AESKW operation by JOSE algorithm name
     *
     * @param ecdhAlgorithm
     *            Algorithm name as string
     * @param fallback
     *            Fallback return value if none of the defined match
     * @return Key length for AESKW operation
     */
    public static int getEcdhAesKwKeyLengthByJoseAlgorithm(String ecdhAlgorithm, int fallback) {
        String algorithm;
        try {
            algorithm = ecdhAlgorithm.substring(ecdhAlgorithm.indexOf("A"));
        } catch (StringIndexOutOfBoundsException e) {
            algorithm = "";
        }
        return getAesKwKeyLengthByJoseAlgorithm(algorithm, fallback);
    }

    /**
     * Generate MAC
     *
     * @param algorithm
     *            Algorithm name as string
     * @param key
     *            Symmetric key as byte array
     * @param message
     *            Input message as byte array
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
     *
     * @param header
     *            JOSE header
     * @param key
     *            Symmetric key as byte array
     * @param iv
     *            Initialization Vector as byte array
     * @param cipherBytes
     *            Ciphertext as byte array
     * @param authTag
     *            Authentication tag as byte array
     * @return Decrypted message as byte array
     * @throws DecryptionFailedException
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
            // TODO move this to some general library initialization code
            removeCryptoStrengthRestriction();

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

    /**
     * Removes JDK crypto restriction.
     * <p>
     * Partially taken from:
     * https://github.com/jruby/jruby/blob/0c345e1b186bd457ebd96143c0816abe93b18fdf/core/src/main/java/org/jruby/util/SecurityHelper.java
     */
    public static void removeCryptoStrengthRestriction() {
        try {
            if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
                Class jceSecurity = Class.forName("javax.crypto.JceSecurity");
                Field isRestricted = jceSecurity.getDeclaredField("isRestricted");
                if (Modifier.isFinal(isRestricted.getModifiers())) {
                    Field modifiers = Field.class.getDeclaredField("modifiers");
                    modifiers.setAccessible(true);
                    modifiers.setInt(isRestricted, isRestricted.getModifiers() & ~Modifier.FINAL);
                    modifiers.setAccessible(false);
                }
                isRestricted.setAccessible(true);
                isRestricted.setBoolean(null, false);
                isRestricted.setAccessible(false);
            }
        } catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | NoSuchAlgorithmException | NoSuchFieldException
                | SecurityException ex) {
            throw new SecurityException("It is not possible to use unrestricted policy with this JDK, " + "consider reconfiguration: "
                    + ex.getLocalizedMessage(), ex);
        }
    }

    /**
     * Splits key with even key length in half, resulting in leftmost values in array with index 0 and the rest in index 1.
     *
     * @param key
     *            key as byte array
     * @return splitted left and right part of the input key
     */
    protected static byte[][] splitKey(byte[] key) {
        int keyLength = key.length / 2;
        byte[][] result = { new byte[keyLength], new byte[keyLength] };
        System.arraycopy(key, 0, result[0], 0, keyLength);
        System.arraycopy(key, keyLength, result[1], 0, keyLength);
        return result;
    }

    protected static byte[] getAadLength(byte[] aad) {
        byte[] result = ByteBuffer.allocate(8).putLong(aad.length * 8).array();
        return result;
    }

    protected static byte[] getMacInput(byte[] aad, byte[] iv, byte[] cipherText) {
        byte[] result = concatByteArrays(aad, iv, cipherText, getAadLength(aad));
        return result;
    }

    /**
     * AEAD encryption unsing AES-CBC + Hmac algorithm
     *
     * @param macAlgorithm
     *            MAC algorithm as String
     * @param key
     *            Symmetric key as byte array
     * @param iv
     *            Initialization Vector as byte array
     * @param plainText
     *            Plaintext as byte array
     * @param aad
     *            Additional authentication data as byte array
     * @return Encrypted message and authentication tag as byte array
     */
    public static byte[][] getAeadCbcHmac(String macAlgorithm, byte[] key, byte[] iv, byte[] plainText, byte[] aad) {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[][] splittedKeys = splitKey(key);
        byte[][] result = { null, null };
        String cipherInstance = "AES/CBC/PKCS7Padding";
        IvParameterSpec parameters = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(splittedKeys[1], "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(cipherInstance, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameters);
            result[0] = cipher.doFinal(plainText);
        } catch (Exception e) {
            e.printStackTrace();
            loggerInstance.log(Crypto.class, "Failed to encrypt with AEAD CBC HMAC. " + e.getMessage(), Logger.LogLevel.ERROR);
        }
        byte[] mac = generateMac(macAlgorithm, splittedKeys[0], getMacInput(aad, iv, result[0]));
        result[1] = getAuthenticationTag(mac);
        return result;
    }

    /**
     * AEAD encryption unsing AES-GCM algorithm
     *
     * @param key
     *            Symmetric key as byte array
     * @param iv
     *            Initialization Vector as byte array
     * @param plainText
     *            Plaintext as byte array
     * @param aad
     *            Additional authentication data as byte array
     * @return Encrypted message and authentication tag as byte array
     */
    public static byte[][] getAeadGcm(byte[] key, byte[] iv, byte[] plainText, byte[] aad) {
        byte[][] result = { null, null };
        KeyParameter keyParameter = new KeyParameter(key);
        AEADParameters aeadParameters = new AEADParameters(keyParameter, 128, iv);
        AEADBlockCipher gcmBlockCipher = new GCMBlockCipher(new AESEngine());
        gcmBlockCipher.init(true, aeadParameters);
        gcmBlockCipher.processAADBytes(aad, 0, aad.length);
        int macLength = aeadParameters.getMacSize() / 8;
        int length = gcmBlockCipher.getOutputSize(plainText.length);
        byte[] output = new byte[length];
        int offset = gcmBlockCipher.processBytes(plainText, 0, plainText.length, output, 0);
        try {
            offset += gcmBlockCipher.doFinal(output, offset);
        } catch (Exception e) {
            e.printStackTrace();
            loggerInstance.log(Crypto.class, "Failed to encrypt with AEAD GCM. " + e.getMessage(), Logger.LogLevel.ERROR);
        }
        result[0] = new byte[offset - macLength];
        System.arraycopy(output, 0, result[0], 0, result[0].length);
        result[1] = new byte[macLength];
        System.arraycopy(output, offset - macLength, result[1], 0, result[1].length);
        return result;
    }

    /**
     * AEAD encryption determined by the JOSE header
     *
     * @param header
     *            JOSE header as byte array
     * @param key
     *            Symmetric key as byte array
     * @param iv
     *            Initialization Vector as byte array
     * @param plainText
     *            Plaintext as byte array
     * @return Encrypted message and authentication tag as byte array
     */
    public static byte[][] getAead(byte[] header, byte[] key, byte[] iv, byte[] plainText) throws NoSuchAlgorithmException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[][] result;
        byte[] aad = null;
        try {
            aad = Decoder.base64UrlEncode(header).getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String encAlg = Decoder.getValueByBase64String(Decoder.base64UrlEncode(header), "enc").toUpperCase();
        switch (encAlg) {
            case "A128CBC-HS256":
                result = getAeadCbcHmac("HmacSHA256", key, iv, plainText, aad);
                break;
            case "A192CBC-HS384":
                result = getAeadCbcHmac("HmacSHA384", key, iv, plainText, aad);
                break;
            case "A256CBC-HS512":
                result = getAeadCbcHmac("HmacSHA512", key, iv, plainText, aad);
                break;
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                result = getAeadGcm(key, iv, plainText, aad);
                break;
            default:
                throw new NoSuchAlgorithmException("Could not determine encryption algorithm or it is not supported: " + encAlg);
        }
        return result;
    }

    /**
     * AES key wrapping algorithm
     *
     * @param cek
     *            Exchanged shared secret content encryption key as byte array
     * @param encryptionKey
     *            Symmetric key to be encrypted with the shared secret as byte array
     * @return Encrypted encryptionKey as byte array
     */
    public static byte[] getAESKeyWrapping(byte[] cek, byte[] encryptionKey) {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[] result;
        SecretKey kek = new SecretKeySpec(cek, "AES");
        SecretKey wrappedKey = new SecretKeySpec(encryptionKey, "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AESKW", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.WRAP_MODE, kek);
            result = cipher.wrap(wrappedKey);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            loggerInstance.log(Crypto.class, "Failed to encrypt with AES key wrapper. " + e.getMessage(), Logger.LogLevel.ERROR);
        }
        return null;
    }

    /**
     * @param ephemeralPoint
     *            Elliptic Curve Point in affine coordinates with x, y and the secret key d as key pair
     * @param staticPubKey
     *            Bouncy Castle Elliptic Curve as targets public key
     * @return
     */
    public static byte[] ecdhAgreement(Point ephemeralPoint, ECPublicKey staticPubKey) {
        if (staticPubKey == null)
            return ecdhAgreement(ephemeralPoint);
        byte[] result;
        ECDHCBasicAgreement ecdhc = new ECDHCBasicAgreement();
        ECParameterSpec parameterSpec = staticPubKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN());
        CipherParameters privateKey = new ECPrivateKeyParameters(ephemeralPoint.getD(), ecDomainParameters);
        ecdhc.init(privateKey);
        CipherParameters publicKey = new ECPublicKeyParameters(staticPubKey.getQ(), ecDomainParameters);
        result = BigIntegers.asUnsignedByteArray(ecdhc.calculateAgreement(publicKey));
        return result;
    }

    /**
     * Fake agreement for invalid points as only the generator is placed in the header, products of it are values of the servers ecdh
     * agreement.
     *
     * @param ephemeralPoint
     *            Elliptic Curve Point in affine coordinates with x, y and the secret key d as key pair
     */
    public static byte[] ecdhAgreement(Point ephemeralPoint) {
        return BigIntegers.asUnsignedByteArray(ephemeralPoint.getX());
    }

    /**
     * Concat key derivation function with additional parameters NIST.SP.800-56Ar3 5.8.2.1.1 The Concatenation Format for FixedInfo
     *
     * @param sharedSecret
     *            Exchanged shared secret as private derivation input
     * @param keyLength
     *            Length of the resulting key
     * @param algorithmID
     *            byte array containing information about the used algorithm
     * @param partyUInfo
     *            byte array containing information from apu
     * @param partyVInfo
     *            byte array containing information from apv
     * @param suppPubInfo
     *            byte array containing the length of the desired output key in bit. For "ECDH-ES", this is length of the key used by the
     *            "enc" algorithm. For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW", this is 128, 192, and 256, respectively.
     *            See: RFC7518 p. 17,18
     * @param suppPrivInfo
     *            Empty octet byte
     */
    public static byte[] concatKDF(byte[] sharedSecret, int keyLength, byte[] algorithmID, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo,
            byte[] suppPrivInfo) {
        byte[] result;
        byte[] fixedInfo = getFixedInfo(algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
        result = concatKDF(sharedSecret, keyLength, fixedInfo);
        return result;
    }

    /**
     * Concat key derivation function with additional parameters NIST.SP.800-56Ar3 5.8.2.1.1 The Concatenation Format for FixedInfo
     *
     * @param sharedSecret
     *            Exchanged shared secret as private derivation input
     * @param keyLength
     *            Length of the resulting key
     * @param algorithmID
     *            byte array containing information about the used algorithm
     * @param partyUInfo
     *            byte array containing information from apu
     * @param partyVInfo
     *            byte array containing information from apv
     */
    public static byte[] concatKDF(byte[] sharedSecret, int keyLength, byte[] algorithmID, byte[] partyUInfo, byte[] partyVInfo) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byte[] suppPubInfo = byteBuffer.putInt(keyLength * 8).array();
        return concatKDF(sharedSecret, keyLength, algorithmID, partyUInfo, partyVInfo, suppPubInfo, new byte[0]);
    }

    /**
     * Concat key derivation function with additional parameters NIST.SP.800-56Ar3 5.8.2.1.1 The Concatenation Format for FixedInfo
     *
     * @param sharedSecret
     *            Exchanged shared secret as private derivation input
     * @param keyLength
     *            Length of the resulting key
     * @param fixedInfo
     *            other/fixed info used by the concat KDF
     */
    public static byte[] concatKDF(byte[] sharedSecret, int keyLength, byte[] fixedInfo) {
        byte[] result = new byte[keyLength];
        SHA256Digest messageDigest = new SHA256Digest();
        ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(messageDigest);
        DerivationParameters derivationParameters = new KDFParameters(sharedSecret, fixedInfo);
        kdf.init(derivationParameters);

        kdf.generateBytes(result, 0, keyLength);
        return result;
    }

    /**
     * Concatenation of the additonal information for the concat KDF
     *
     * @param algorithmID
     *            byte array containing information about the used algorithm
     * @param partyUInfo
     *            byte array containing information from apu
     * @param partyVInfo
     *            byte array containing information from apv
     * @param suppPubInfo
     *            byte array containing the length of the desired output key in bit. For "ECDH-ES", this is length of the key used by the
     *            "enc" algorithm. For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW", this is 128, 192, and 256, respectively.
     *            See: RFC7518 p. 17,18
     * @param suppPrivInfo
     *            Empty octet byte
     * @return fixedInfo
     */
    public static byte[] getFixedInfo(byte[] algorithmID, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo) {
        return concatByteArrays(algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
    }

    /**
     * Concatenates all given byte arrays to a single byte array
     *
     * @param arrays
     * @return concatenatedArrays
     */
    protected static byte[] concatByteArrays(byte[]... arrays) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            for (byte[] array : arrays) {
                byteArrayOutputStream.write(array);
            }
        } catch (IOException e) {
            e.printStackTrace();
            loggerInstance.log(Crypto.class, "Failed concatenating byte arrays. " + e.getMessage(), Logger.LogLevel.ERROR);
        }
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Splitts MAC to get authentication tag
     *
     * @param mac
     *            message authentication code
     * @return authenticationTag
     */
    public static byte[] getAuthenticationTag(byte[] mac) {
        byte[] result = new byte[mac.length / 2];
        System.arraycopy(mac, 0, result, 0, result.length);
        return result;
    }

    /**
     * Concatenates the length of a string in a four byte array in front of the string
     *
     * @param info
     *            String to be concatenated with its lengh in bytes
     * @return array of the concatenated length and the input string
     */
    public static byte[] concatLengthInfo(String info) {
        int length = info.length();
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + length);
        byteBuffer.putInt(length);
        for (int i = 0; i < length; ++i) {
            byteBuffer.put(i + 4, (byte) info.charAt(i));
        }
        return byteBuffer.array();
    }
}
