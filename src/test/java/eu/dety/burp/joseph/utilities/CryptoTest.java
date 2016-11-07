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

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CryptoTest {

    @Test
    public void testGenerateMac() {
        byte[] message = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9".getBytes();
        byte[] expected = new byte[] { (byte) 38, (byte) 136, (byte) 117, (byte) 71, (byte) 103, (byte) 88, (byte) 206, (byte) 68, (byte) 111, (byte) 14,
                (byte) 74, (byte) 175, (byte) 222, (byte) 204, (byte) 160, (byte) 155, (byte) 150, (byte) 50, (byte) 43, (byte) 193, (byte) 162, (byte) 225,
                (byte) 40, (byte) 89, (byte) 169, (byte) 184, (byte) 74, (byte) 218, (byte) 12, (byte) 92, (byte) 179, (byte) 101 };

        assertArrayEquals(expected, Crypto.generateMac("HmacSHA256", "secret".getBytes(), message));
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

}
