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

import eu.dety.burp.joseph.BurpExtenderCallbacksMock;

import eu.dety.burp.joseph.attacks.invalid_curve.InvalidCurveInfo;
import eu.dety.burp.joseph.attacks.invalid_curve.Point;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.*;

import org.junit.Test;
import static org.junit.Assert.*;

public class CryptoTest {

    @Test
    public void testGenerateMac() {
        byte[] message = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9".getBytes();
        byte[] expected = new byte[] { (byte) 38, (byte) 136, (byte) 117, (byte) 71, (byte) 103, (byte) 88, (byte) 206, (byte) 68, (byte) 111, (byte) 14,
                (byte) 74, (byte) 175, (byte) 222, (byte) 204, (byte) 160, (byte) 155, (byte) 150, (byte) 50, (byte) 43, (byte) 193, (byte) 162, (byte) 225,
                (byte) 40, (byte) 89, (byte) 169, (byte) 184, (byte) 74, (byte) 218, (byte) 12, (byte) 92, (byte) 179, (byte) 101 };

        assertArrayEquals(expected, Crypto.generateMac("HmacSHA256", "secret".getBytes(), message));

        byte[] macInput = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
                74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
                116, 104, 101, 40, 57, 83, (byte) 181, 119, 33, (byte) 133, (byte) 148, (byte) 198, (byte) 185, (byte) 243, 24, (byte) 152, (byte) 230, 6, 75,
                (byte) 129, (byte) 223, 127, 19, (byte) 210, 82, (byte) 183, (byte) 230, (byte) 168, 33, (byte) 215, 104, (byte) 143, 112, 56, 102, 0, 0, 0, 0,
                0, 0, 1, (byte) 152 };
        byte[] key = { 4, (byte) 211, 31, (byte) 197, 84, (byte) 157, (byte) 252, (byte) 254, 11, 100, (byte) 157, (byte) 250, 63, (byte) 170, 106, (byte) 206,
                107, 124, (byte) 212, 45, 111, 107, 9, (byte) 219, (byte) 200, (byte) 177, 0, (byte) 240, (byte) 143, (byte) 156, 44, (byte) 207 };
        expected = new byte[] { 83, 73, (byte) 191, 98, 104, (byte) 205, (byte) 211, (byte) 128, (byte) 201, (byte) 189, (byte) 199, (byte) 133, 32, 38,
                (byte) 194, 85, 9, 84, (byte) 229, (byte) 201, (byte) 219, (byte) 135, 44, (byte) 252, (byte) 145, 102, (byte) 179, (byte) 140, 105, 86,
                (byte) 229, 116 };
        byte[] actual = Crypto.generateMac("HmacSHA256", Crypto.splitKey(key)[0], macInput);
        assertArrayEquals(expected, actual);

    }

    @Test
    public void testGetAesKeyLengthByJoseAlgorithmReturnsCorrectKeyLength() {
        assertEquals(16, Crypto.getAesKeyLengthByJoseAlgorithm("A128GCM", 100));
        assertEquals(16, Crypto.getAesKeyLengthByJoseAlgorithm("A128CBC-HS256", 100));
        assertEquals(24, Crypto.getAesKeyLengthByJoseAlgorithm("A192GCM", 100));
        assertEquals(24, Crypto.getAesKeyLengthByJoseAlgorithm("A192CBC-HS384", 100));
        assertEquals(32, Crypto.getAesKeyLengthByJoseAlgorithm("A256GCM", 100));
        assertEquals(32, Crypto.getAesKeyLengthByJoseAlgorithm("A256CBC-HS512", 100));
        assertEquals(100, Crypto.getAesKeyLengthByJoseAlgorithm("InvalidAlg", 100));
    }

    @Test
    public void testGetJoseKeyLengthByJoseAlgorithmReturnsCorrectKeyLength() {
        assertEquals(16, Crypto.getJoseKeyLengthByJoseAlgorithm("A128GCM", 100));
        assertEquals(32, Crypto.getJoseKeyLengthByJoseAlgorithm("A128CBC-HS256", 100));
        assertEquals(24, Crypto.getJoseKeyLengthByJoseAlgorithm("A192GCM", 100));
        assertEquals(48, Crypto.getJoseKeyLengthByJoseAlgorithm("A192CBC-HS384", 100));
        assertEquals(32, Crypto.getJoseKeyLengthByJoseAlgorithm("A256GCM", 100));
        assertEquals(64, Crypto.getJoseKeyLengthByJoseAlgorithm("A256CBC-HS512", 100));
        assertEquals(100, Crypto.getJoseKeyLengthByJoseAlgorithm("InvalidAlg", 100));
    }

    @Test
    public void testAes128CBCDecryption() {
        String header = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        byte[] key = new byte[] { (byte) 203, (byte) 149, (byte) 25, (byte) 91, (byte) 80, (byte) 61, (byte) 177, (byte) 225, (byte) 234, (byte) 189,
                (byte) 180, (byte) 18, (byte) 236, (byte) 116, (byte) 74, (byte) 190, (byte) 133, (byte) 116, (byte) 187, (byte) 231, (byte) 76, (byte) 185,
                (byte) 187, (byte) 180, (byte) 173, (byte) 225, (byte) 196, (byte) 240, (byte) 249, (byte) 201, (byte) 166, (byte) 19 };
        byte[] iv = Base64.decodeBase64("BpP4TNTz4uYv9cpu2VAnfw");
        byte[] ciphertext = Base64.decodeBase64("QHB8R67pbL3g8oH8ytnoDfXMC-OGVZbpq_VD48Ppu4sj6-MR3Ul2JVMf5xPXtVE-m7xCGiApaO3iXSHE32GGUarCYG2STBMrCpLbiQQKnnU");
        byte[] authTag = Base64.decodeBase64("Oe26--wySamfIU1emS-iuA");

        byte[] content = new byte[0];
        try {
            content = Crypto.decryptAES(header, key, iv, ciphertext, authTag);
        } catch (DecryptionFailedException e) {
            e.printStackTrace();
        }
        byte[] expectedContent = new byte[] { (byte) 123, (byte) 34, (byte) 109, (byte) 115, (byte) 103, (byte) 34, (byte) 58, (byte) 34, (byte) 84,
                (byte) 104, (byte) 105, (byte) 115, (byte) 32, (byte) 105, (byte) 115, (byte) 32, (byte) 116, (byte) 104, (byte) 101, (byte) 32, (byte) 104,
                (byte) 105, (byte) 100, (byte) 100, (byte) 101, (byte) 110, (byte) 32, (byte) 109, (byte) 101, (byte) 115, (byte) 115, (byte) 97, (byte) 103,
                (byte) 101, (byte) 59, (byte) 32, (byte) 107, (byte) 101, (byte) 121, (byte) 58, (byte) 32, (byte) 53, (byte) 49, (byte) 50, (byte) 59,
                (byte) 32, (byte) 101, (byte) 110, (byte) 99, (byte) 58, (byte) 32, (byte) 65, (byte) 49, (byte) 50, (byte) 56, (byte) 67, (byte) 66,
                (byte) 67, (byte) 45, (byte) 72, (byte) 83, (byte) 50, (byte) 53, (byte) 54, (byte) 34, (byte) 125 };

        assertArrayEquals(expectedContent, content);
    }

    @Test
    public void testAes256CBCDecryption() {
        String header = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0";
        byte[] key = new byte[] { (byte) 20, (byte) 2, (byte) 166, (byte) 192, (byte) 202, (byte) 83, (byte) 90, (byte) 177, (byte) 16, (byte) 180, (byte) 250,
                (byte) 194, (byte) 208, (byte) 31, (byte) 198, (byte) 120, (byte) 52, (byte) 89, (byte) 246, (byte) 211, (byte) 102, (byte) 219, (byte) 35,
                (byte) 143, (byte) 129, (byte) 61, (byte) 234, (byte) 127, (byte) 183, (byte) 208, (byte) 177, (byte) 232, (byte) 43, (byte) 11, (byte) 160,
                (byte) 44, (byte) 144, (byte) 86, (byte) 3, (byte) 123, (byte) 39, (byte) 6, (byte) 48, (byte) 242, (byte) 179, (byte) 95, (byte) 54,
                (byte) 210, (byte) 168, (byte) 138, (byte) 29, (byte) 190, (byte) 144, (byte) 179, (byte) 111, (byte) 137 };
        byte[] iv = Base64.decodeBase64("uYkZ4KxK3B6jvAa40XZNAw");
        byte[] ciphertext = Base64.decodeBase64("cY_LgTVBiP434RN9EWfFlgnal7amPk4X3DxEZW1s1HUJZ0OJNKDW3_fEEz1i4JxVxTW26mN9845IG4qwqLfDLSlvlH2k9LGJxqmt2OT_Lrw");
        byte[] authTag = Base64.decodeBase64("Er4GpH-oYEVwostxXjbM1yORlR3bOznwjXBKEdOzyKU");

        byte[] content = new byte[0];
        try {
            content = Crypto.decryptAES(header, key, iv, ciphertext, authTag);
        } catch (DecryptionFailedException e) {
            e.printStackTrace();
        }
        byte[] expectedContent = new byte[] { (byte) 123, (byte) 34, (byte) 109, (byte) 115, (byte) 103, (byte) 34, (byte) 58, (byte) 34, (byte) 84,
                (byte) 104, (byte) 105, (byte) 115, (byte) 32, (byte) 105, (byte) 115, (byte) 32, (byte) 116, (byte) 104, (byte) 101, (byte) 32, (byte) 104,
                (byte) 105, (byte) 100, (byte) 100, (byte) 101, (byte) 110, (byte) 32, (byte) 109, (byte) 101, (byte) 115, (byte) 115, (byte) 97, (byte) 103,
                (byte) 101, (byte) 59, (byte) 32, (byte) 107, (byte) 101, (byte) 121, (byte) 58, (byte) 32, (byte) 49, (byte) 48, (byte) 50, (byte) 52,
                (byte) 59, (byte) 32, (byte) 101, (byte) 110, (byte) 99, (byte) 58, (byte) 32, (byte) 65, (byte) 50, (byte) 53, (byte) 54, (byte) 67,
                (byte) 66, (byte) 67, (byte) 45, (byte) 72, (byte) 83, (byte) 53, (byte) 49, (byte) 50, (byte) 34, (byte) 125 };

        assertArrayEquals(expectedContent, content);
    }

    @Test
    public void testAes128GCMDecryption() {
        String header = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0";
        byte[] key = new byte[] { (byte) 158, (byte) 35, (byte) 228, (byte) 174, (byte) 92, (byte) 219, (byte) 18, (byte) 157, (byte) 230, (byte) 112,
                (byte) 161, (byte) 200, (byte) 253, (byte) 76, (byte) 126, (byte) 56 };
        byte[] iv = Base64.decodeBase64("Y7m7acdZN1VjHfsu");
        byte[] ciphertext = Base64.decodeBase64("L2gRqr2qaLtyrY2SJPMHh7a4Rh_Ek7eWQiz-iPCRiXB6SZG_uaBPGomFF9NWhycuQ2W-RB65VZUwTwBk");
        byte[] authTag = Base64.decodeBase64("__dvE3RoE_ffKi7MnvzDOw");

        byte[] content = new byte[0];
        try {
            content = Crypto.decryptAES(header, key, iv, ciphertext, authTag);
        } catch (DecryptionFailedException e) {
            e.printStackTrace();
        }
        byte[] expectedContent = new byte[] { (byte) 123, (byte) 34, (byte) 109, (byte) 115, (byte) 103, (byte) 34, (byte) 58, (byte) 34, (byte) 84,
                (byte) 104, (byte) 105, (byte) 115, (byte) 32, (byte) 105, (byte) 115, (byte) 32, (byte) 116, (byte) 104, (byte) 101, (byte) 32, (byte) 104,
                (byte) 105, (byte) 100, (byte) 100, (byte) 101, (byte) 110, (byte) 32, (byte) 109, (byte) 101, (byte) 115, (byte) 115, (byte) 97, (byte) 103,
                (byte) 101, (byte) 59, (byte) 32, (byte) 107, (byte) 101, (byte) 121, (byte) 58, (byte) 32, (byte) 53, (byte) 49, (byte) 50, (byte) 59,
                (byte) 32, (byte) 101, (byte) 110, (byte) 99, (byte) 58, (byte) 32, (byte) 65, (byte) 49, (byte) 50, (byte) 56, (byte) 71, (byte) 67,
                (byte) 77, (byte) 34, (byte) 125 };

        assertArrayEquals(expectedContent, content);
    }

    @Test
    public void testAes256GCMDecryption() {
        String header = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        byte[] key = new byte[] { (byte) 177, (byte) 161, (byte) 244, (byte) 128, (byte) 84, (byte) 143, (byte) 225, (byte) 115, (byte) 63, (byte) 180,
                (byte) 3, (byte) 255, (byte) 107, (byte) 154, (byte) 212, (byte) 246, (byte) 138, (byte) 7, (byte) 110, (byte) 91, (byte) 112, (byte) 46,
                (byte) 34, (byte) 105, (byte) 47, (byte) 130, (byte) 203, (byte) 46, (byte) 122, (byte) 234, (byte) 64, (byte) 252 };
        byte[] iv = Base64.decodeBase64("48V1_ALb6US04U3b");
        byte[] ciphertext = Base64.decodeBase64("5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A");
        byte[] authTag = Base64.decodeBase64("XFBoMYUZodetZdvTiFvSkQ");

        byte[] content = new byte[0];
        try {
            content = Crypto.decryptAES(header, key, iv, ciphertext, authTag);
        } catch (DecryptionFailedException e) {
            e.printStackTrace();
        }
        byte[] expectedContent = new byte[] { (byte) 84, (byte) 104, (byte) 101, (byte) 32, (byte) 116, (byte) 114, (byte) 117, (byte) 101, (byte) 32,
                (byte) 115, (byte) 105, (byte) 103, (byte) 110, (byte) 32, (byte) 111, (byte) 102, (byte) 32, (byte) 105, (byte) 110, (byte) 116, (byte) 101,
                (byte) 108, (byte) 108, (byte) 105, (byte) 103, (byte) 101, (byte) 110, (byte) 99, (byte) 101, (byte) 32, (byte) 105, (byte) 115, (byte) 32,
                (byte) 110, (byte) 111, (byte) 116, (byte) 32, (byte) 107, (byte) 110, (byte) 111, (byte) 119, (byte) 108, (byte) 101, (byte) 100, (byte) 103,
                (byte) 101, (byte) 32, (byte) 98, (byte) 117, (byte) 116, (byte) 32, (byte) 105, (byte) 109, (byte) 97, (byte) 103, (byte) 105, (byte) 110,
                (byte) 97, (byte) 116, (byte) 105, (byte) 111, (byte) 110, (byte) 46 };

        assertArrayEquals(expectedContent, content);
    }

    @Test
    public void testAES256() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Crypto.removeCryptoStrengthRestriction();

        Cipher encryptCipher = Cipher.getInstance("AES/CBC/NoPadding", Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
        IvParameterSpec encryptIv = new IvParameterSpec(new byte[16]);
        SecretKey encryptKey = new SecretKeySpec(new byte[32], "AES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);

    }

    @Test
    public void getEcdhAesKwKeyLengthByJoseAlgorithmTest() {
        String[] algorithms = { "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW" };
        assertEquals(16, Crypto.getEcdhAesKwKeyLengthByJoseAlgorithm(algorithms[0], 16));
        assertEquals(16, Crypto.getEcdhAesKwKeyLengthByJoseAlgorithm(algorithms[1], 16));
        assertEquals(24, Crypto.getEcdhAesKwKeyLengthByJoseAlgorithm(algorithms[2], 16));
        assertEquals(32, Crypto.getEcdhAesKwKeyLengthByJoseAlgorithm(algorithms[3], 16));
    }

    @Test
    public void concatKDF128Test() {
        // RFC JWA Digist is SHA-256 16 byte = 128, 32 byte = 256
        byte[] z = { (byte) 158, 86, (byte) 217, 29, (byte) 129, 113, 53, (byte) 211, 114, (byte) 131, 66, (byte) 131, (byte) 191, (byte) 132, 38, (byte) 156,
                (byte) 251, 49, 110, (byte) 163, (byte) 218, (byte) 128, 106, 72, (byte) 246, (byte) 218, (byte) 167, 121, (byte) 140, (byte) 254, (byte) 144,
                (byte) 196 };
        String algorithmID = "A128GCM";
        String partyUInfo = "Alice";
        String partyVInfo = "Bob";
        byte[] actual = Crypto.concatKDF(z, 16, Crypto.concatLengthInfo(algorithmID), Crypto.concatLengthInfo(partyUInfo), Crypto.concatLengthInfo(partyVInfo));
        assertEquals(128, actual.length * 8);
    }

    @Test
    public void concatKDF192Test() {
        // RFC JWA Digist is SHA-256 16 byte = 128, 32 byte = 256
        int keyLength = 192;
        byte[] sharedSecret = new byte[16];
        byte[] algorithmID = new byte[4];
        byte[] partyUInfo = new byte[4];
        byte[] partyVInfo = new byte[4];
        byte[] output = new byte[24]; // 192 bit = 24 byte
        assertTrue(output.length * 8 == Crypto.concatKDF(sharedSecret, keyLength, algorithmID, partyUInfo, partyVInfo).length);
    }

    @Test
    public void concatKDF256Test() {
        // RFC JWA Digist is SHA-256 16 byte = 128, 32 byte = 256
        int keyLength = 256;
        byte[] sharedSecret = new byte[16];
        byte[] algorithmID = new byte[4];
        byte[] partyUInfo = new byte[4];
        byte[] partyVInfo = new byte[4];
        byte[] output = new byte[32]; // 256 bit = 32 byte
        assertTrue(output.length * 8 == Crypto.concatKDF(sharedSecret, keyLength, algorithmID, partyUInfo, partyVInfo).length);
    }

    @Test
    public void getFixedInfoTest() {
        byte[] algorithmID = Crypto.concatLengthInfo(StringUtils.newStringUtf8("A128CBC-HS256".getBytes()));
        byte[] partyUInfo = Crypto.concatLengthInfo("");
        byte[] partyVInfo = Crypto.concatLengthInfo("");
        byte[] result = Crypto.getFixedInfo(algorithmID, partyUInfo, partyVInfo, ByteBuffer.allocate(4).putInt(256).array(), new byte[0]);
        String expected = ByteUtils.toHexString("\u0000\u0000\u0000\rA128CBC-HS256\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000"
                .getBytes());
        assertEquals(expected, ByteUtils.toHexString(result));
        assertEquals(29, result.length);
    }

    @Test
    public void concatLengthInfoTest() {
        byte[] result = Crypto.concatLengthInfo("");
        assertEquals(4, result.length);
        byte[] expected1 = { 0, 0, 0, 0 };
        assertArrayEquals(expected1, result);
        result = Crypto.concatLengthInfo("Hallo");
        assertEquals(9, result.length);
        byte[] expected2 = { 0, 0, 0, 5, 72, 97, 108, 108, 111 };
        assertArrayEquals(expected2, result);
    }

    @Test
    public void getAESKeyWrappingTest() {
        byte[] derivedKey = Base64.decodeBase64("GawgguFyGrWKav7AX4VKUg");
        byte[] wrappedKey = { 4, (byte) 211, 31, (byte) 197, 84, (byte) 157, (byte) 252, (byte) 254, 11, 100, (byte) 157, (byte) 250, 63, (byte) 170, 106,
                (byte) 206, 107, 124, (byte) 212, 45, 111, 107, 9, (byte) 219, (byte) 200, (byte) 177, 0, (byte) 240, (byte) 143, (byte) 156, 44, (byte) 207 };
        byte[] expected = { (byte) 232, (byte) 160, 123, (byte) 211, (byte) 183, 76, (byte) 245, (byte) 132, (byte) 200, (byte) 128, 123, 75, (byte) 190,
                (byte) 216, 22, 67, (byte) 201, (byte) 138, (byte) 193, (byte) 186, 9, 91, 122, 31, (byte) 246, 90, 28, (byte) 139, 57, 3, 76, 124, (byte) 193,
                11, 98, 37, (byte) 173, 61, 104, 57 };
        byte[] actual = Crypto.getAESKeyWrapping(derivedKey, wrappedKey);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void ecdhTest() throws ParseException {
        InvalidCurveInfo ici = new InvalidCurveInfo(new BurpExtenderCallbacksMock());
        ECPublicKey pub = (ECPublicKey) ici.generateValidKey().getPublic();
        byte[] actual = Crypto.ecdhAgreement(new Point(null, new BigInteger("3"), null, null), pub);
        assertNotNull(actual);
        String pubKey = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"}";
        Object publicKeyValueJson;
        publicKeyValueJson = new JSONParser().parse(pubKey);
        ECPublicKey ecPub = Converter.getECPublicKeyByJwk(publicKeyValueJson);
        Point jwePoint = new Point(new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
                Base64.decodeInteger("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo".getBytes()),
                Base64.decodeInteger("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0".getBytes()),
                Base64.decodeInteger("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps".getBytes()));
        actual = Crypto.ecdhAgreement(jwePoint, ecPub);
        System.out.println(ByteUtils.toHexString(Base64.decodeInteger("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo".getBytes()).toByteArray()));
        System.out.println(Base64.decodeInteger("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo".getBytes()).toByteArray().length);
        // System.out.println(actual.length);
        byte[] expected = { (byte) 158, 86, (byte) 217, 29, (byte) 129, 113, 53, (byte) 211, 114, (byte) 131, 66, (byte) 131, (byte) 191, (byte) 132, 38,
                (byte) 156, (byte) 251, 49, 110, (byte) 163, (byte) 218, (byte) 128, 106, 72, (byte) 246, (byte) 218, (byte) 167, 121, (byte) 140, (byte) 254,
                (byte) 144, (byte) 196 };
        assertArrayEquals(expected, actual);

    }

    @Test
    public void getAeadTest() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        InvalidCurveInfo invalidCurveInfo = new InvalidCurveInfo(new BurpExtenderCallbacksMock());
        Point point = invalidCurveInfo.getPointFromECKeyPair(invalidCurveInfo.generateValidKey());
        byte[] header = invalidCurveInfo.getHeader(point, "", "");
        byte[][] result;
        byte[] plaintext = new byte[160];
        byte[] iv = new byte[16];
        byte[] key = new byte[16];
        result = Crypto.getAead(header, key, iv, plaintext);
        assertNotNull(result[0]);
        assertNotNull(result[1]);
    }

    @Test
    public void splitKeyTest() {
        byte[] testcase = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[][] actual = Crypto.splitKey(testcase);
        byte[] leftHalf = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] rightHalf = { 9, 10, 11, 12, 13, 14, 15, 16 };
        assertEquals(8, actual[0].length);
        assertEquals(8, actual[1].length);
        assertArrayEquals(leftHalf, actual[0]);
        assertArrayEquals(rightHalf, actual[1]);
    }

    @Test
    public void getAadLengthTest() {
        byte[] aad = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74,
                66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48 };
        byte[] expected = { 0, 0, 0, 0, 0, 0, 1, (byte) 152 };
        byte[] actual = Crypto.getAadLength(aad);
        assertEquals(8, actual.length);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void getMacInputTest() {
        byte[] aad = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74,
                66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48 };
        byte[] iv = { 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101 };
        byte[] ciphertext = { 40, 57, 83, (byte) 181, 119, 33, (byte) 133, (byte) 148, (byte) 198, (byte) 185, (byte) 243, 24, (byte) 152, (byte) 230, 6, 75,
                (byte) 129, (byte) 223, 127, 19, (byte) 210, 82, (byte) 183, (byte) 230, (byte) 168, 33, (byte) 215, 104, (byte) 143, 112, 56, 102 };
        byte[] expected = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
                74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
                116, 104, 101, 40, 57, 83, (byte) 181, 119, 33, (byte) 133, (byte) 148, (byte) 198, (byte) 185, (byte) 243, 24, (byte) 152, (byte) 230, 6, 75,
                (byte) 129, (byte) 223, 127, 19, (byte) 210, 82, (byte) 183, (byte) 230, (byte) 168, 33, (byte) 215, 104, (byte) 143, 112, 56, 102, 0, 0, 0, 0,
                0, 0, 1, (byte) 152 };
        byte[] actual = Crypto.getMacInput(aad, iv, ciphertext);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void getAuthenticationTagTest() {
        byte[] mac = new byte[] { 83, 73, (byte) 191, 98, 104, (byte) 205, (byte) 211, (byte) 128, (byte) 201, (byte) 189, (byte) 199, (byte) 133, 32, 38,
                (byte) 194, 85, 9, 84, (byte) 229, (byte) 201, (byte) 219, (byte) 135, 44, (byte) 252, (byte) 145, 102, (byte) 179, (byte) 140, 105, 86,
                (byte) 229, 116 };
        byte[] expected = { 83, 73, (byte) 191, 98, 104, (byte) 205, (byte) 211, (byte) 128, (byte) 201, (byte) 189, (byte) 199, (byte) 133, 32, 38,
                (byte) 194, 85 };
        byte[] actual = Crypto.getAuthenticationTag(mac);
        assertArrayEquals(expected, actual);
    }

    @Test
    public void getAeadCbcHmacTest() {
        byte[] key = { 4, (byte) 211, 31, (byte) 197, 84, (byte) 157, (byte) 252, (byte) 254, 11, 100, (byte) 157, (byte) 250, 63, (byte) 170, 106, (byte) 206,
                107, 124, (byte) 212, 45, 111, 107, 9, (byte) 219, (byte) 200, (byte) 177, 0, (byte) 240, (byte) 143, (byte) 156, 44, (byte) 207 };
        byte[] iv = { 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101 };
        byte[] aad = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74,
                66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48 };
        byte[] plaintext = { 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46 };
        byte[][] expected = {
                { 40, 57, 83, (byte) 181, 119, 33, (byte) 133, (byte) 148, (byte) 198, (byte) 185, (byte) 243, 24, (byte) 152, (byte) 230, 6, 75, (byte) 129,
                        (byte) 223, 127, 19, (byte) 210, 82, (byte) 183, (byte) 230, (byte) 168, 33, (byte) 215, 104, (byte) 143, 112, 56, 102 },
                { 83, 73, (byte) 191, 98, 104, (byte) 205, (byte) 211, (byte) 128, (byte) 201, (byte) 189, (byte) 199, (byte) 133, 32, 38, (byte) 194, 85 } };
        byte[][] actual = Crypto.getAeadCbcHmac("HmacSHA256", key, iv, plaintext, aad);
        assertArrayEquals(expected[0], actual[0]);
        assertArrayEquals(expected[1], actual[1]);
    }

    @Test
    public void getAeadGcmTest() {
        byte[] key = { (byte) 177, (byte) 161, (byte) 244, (byte) 128, 84, (byte) 143, (byte) 225, 115, 63, (byte) 180, 3, (byte) 255, 107, (byte) 154,
                (byte) 212, (byte) 246, (byte) 138, 7, 110, 91, 112, 46, 34, 105, 47, (byte) 130, (byte) 203, 46, 122, (byte) 234, 64, (byte) 252 };
        byte[] iv = { (byte) 227, (byte) 197, 117, (byte) 252, 2, (byte) 219, (byte) 233, 68, (byte) 180, (byte) 225, 77, (byte) 219 };
        byte[] aad = { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
                54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81 };
        byte[] plaintext = { 84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32, 111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110,
                99, 101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108, 101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105, 110,
                97, 116, 105, 111, 110, 46 };

        byte[] expectedCiphertext = { (byte) 229, (byte) 236, (byte) 166, (byte) 241, 53, (byte) 191, 115, (byte) 196, (byte) 174, 43, 73, 109, 39, 122,
                (byte) 233, 96, (byte) 140, (byte) 206, 120, 52, 51, (byte) 237, 48, 11, (byte) 190, (byte) 219, (byte) 186, 80, 111, 104, 50, (byte) 142, 47,
                (byte) 167, 59, 61, (byte) 181, 127, (byte) 196, 21, 40, 82, (byte) 242, 32, 123, (byte) 143, (byte) 168, (byte) 226, 73, (byte) 216,
                (byte) 176, (byte) 144, (byte) 138, (byte) 247, 106, 60, 16, (byte) 205, (byte) 160, 109, 64, 63, (byte) 192 };
        byte[] expectedAuthTag = { 92, 80, 104, 49, (byte) 133, 25, (byte) 161, (byte) 215, (byte) 173, 101, (byte) 219, (byte) 211, (byte) 136, 91,
                (byte) 210, (byte) 145 };
        byte[][] actual = Crypto.getAeadGcm(key, iv, plaintext, aad);
        assertArrayEquals(expectedCiphertext, actual[0]);
        assertArrayEquals(expectedAuthTag, actual[1]);
    }
}
