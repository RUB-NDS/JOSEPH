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

import org.json.JSONObject;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class DecoderTest {
    @Test
    public void getEncodedWithBytesInputReturnsCorrectBase64UrlEncodedString() {
        byte[] input = new byte[] { 84, 101, 115, 116, 32, 73, 110, 112, 117, 116 };

        assertEquals("VGVzdCBJbnB1dA", Decoder.getEncoded(input));
    }

    @Test
    public void getEncodedWithStringInputReturnsCorrectBase64UrlEncodedString() {
        String input = "Test Input";

        assertEquals("VGVzdCBJbnB1dA", Decoder.getEncoded(input));
    }

    @Test
    public void getDecodedWithBase64UrlStringInputReturnsCorrectDecodedString() {
        String input = "VGVzdCBJbnB1dA";

        assertEquals("Test Input", Decoder.getDecoded(input));
    }

    @Test
    public void getDecodedGetEncodedWithStringInputReturnsSameString() {
        String input = "Test Input";

        assertEquals("Test Input", Decoder.getDecoded(Decoder.getEncoded(input)));
    }

    @Test
    public void getComponentsWithThreeComponentJwtInputReturnsStringArrayWithThreeComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        String[] expected = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg" };

        assertArrayEquals(expected, Decoder.getComponents(token));
    }

    @Test
    public void getComponentsWithFourComponentJwtInputReturnsStringArrayWithFourComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String[] expected = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" };

        assertArrayEquals(expected, Decoder.getComponents(token));
    }

    @Test
    public void getComponentsWithThreeComponentJwtAndAssureLengthInputReturnsStringArrayWithThreeComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        String[] expected = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg" };

        assertArrayEquals(expected, Decoder.getComponents(token, 3));
    }

    @Test
    public void getComponentsWithTwoComponentJwtAndAssureLengthInputReturnsStringArrayWithThreeComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9";
        String[] expected = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "" };

        assertArrayEquals(expected, Decoder.getComponents(token, 3));
    }

    @Test
    public void getComponentsWithFiveComponentJwtAndAssureLengthInputReturnsStringArrayWithThreeComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9";
        String[] expected = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg" };

        assertArrayEquals(expected, Decoder.getComponents(token, 3));
    }

    @Test
    public void concatComponentsWithThreeStringsArrayInputReturnsCorrectlyConcatenatedString() {
        String[] input = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg" };
        String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertEquals(expected, Decoder.concatComponents(input));
    }

    @Test
    public void concatComponentsWithThreeStringsArrayIncludingEmptyStringInputReturnsCorrectlyConcatenatedString() {
        String[] input = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "" };
        String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.";

        assertEquals(expected, Decoder.concatComponents(input));
    }

    @Test
    public void concatComponentsWithFiveStringsArrayStringInputReturnsCorrectlyConcatenatedString() {
        String[] input = new String[] { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9" };
        String expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9";

        assertEquals(expected, Decoder.concatComponents(input));
    }

    @Test
    public void getDecodedJsonWithBase64EncodedJsonStringInputReturnsCorrectJsonObject() {
        JSONAssert.assertEquals(new JSONObject().put("some", "payload"), Decoder.getDecodedJson("eyJzb21lIjoicGF5bG9hZCJ9"), true);
    }

    @Test
    public void getDecodedJsonWithEmptyStringInputReturnsEmptyJsonObject() {
        JSONAssert.assertEquals(new JSONObject(), Decoder.getDecodedJson(""), true);
    }

    @Test
    public void getDecodedJsonWithInvalidInputReturnsEmptyJsonObject() {
        JSONAssert.assertEquals(new JSONObject(), Decoder.getDecodedJson("Invalid Base64"), true);
    }

    @Test
    public void getJsonComponentsWithTwoComponentBase64StringInputReturnsArrayWithTwoJsonObjects() {
        JSONObject[] expected = new JSONObject[2];
        expected[0] = new JSONObject().put("alg", "HS256").put("typ", "JWT");
        expected[1] = new JSONObject().put("some", "payload");

        JSONObject[] result = Decoder.getJsonComponents("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9");
        assertEquals(expected.length, result.length);

        for (int i = 0; i < result.length; i++) {
            JSONAssert.assertEquals(expected[i], result[i], true);
        }
    }

    @Test
    public void getJsonComponentsWithTwoComponentBase64StringIncludingComponentInputReturnsArrayWithTwoJsonObjects() {
        JSONObject[] expected = new JSONObject[2];
        expected[0] = new JSONObject().put("alg", "HS256").put("typ", "JWT");
        expected[1] = new JSONObject();

        JSONObject[] result = Decoder.getJsonComponents("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.");
        assertEquals(expected.length, result.length);

        for (int i = 0; i < result.length; i++) {
            JSONAssert.assertEquals(expected[i], result[i], true);
        }
    }

    @Test
    public void getJsonComponentsWithFourComponentBase64StringInputReturnsArrayWithFourJsonObjects() {
        JSONObject[] expected = new JSONObject[4];
        expected[0] = new JSONObject().put("alg", "HS256").put("typ", "JWT");
        expected[1] = new JSONObject().put("some", "payload");
        expected[2] = new JSONObject().put("another", "payload");
        expected[3] = new JSONObject().put("and even", "more");

        JSONObject[] result = Decoder
                .getJsonComponents("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.eyJhbm90aGVyIjoicGF5bG9hZCJ9.eyJhbmQgZXZlbiI6Im1vcmUifQ");
        assertEquals(expected.length, result.length);

        for (int i = 0; i < result.length; i++) {
            JSONAssert.assertEquals(expected[i], result[i], true);
        }
    }

    @Test
    public void convertBytesToHex() {
        byte[] input = new byte[] { 0, 84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116 };
        String output = "00 54 68 69 73 20 69 73 20 61 20 74 65 73 74";

        assertEquals(output, Decoder.bytesToHex(input));
    }

    @Test
    public void convertHexToBytes() {
        String input = "54 68 69 73 20 69 73 20 61 20 74 65 73 74";
        byte[] output = new byte[] { 84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116 };

        assertArrayEquals(output, Decoder.hexToBytes(input));
    }

    @Test
    public void convertHexToBytesWithWrongByteReturnsEmptyByteArray() {
        String input = "54 68 69 73 20 69 73 20 61 20 74 65 73 7";
        byte[] output = new byte[] {};

        assertArrayEquals(output, Decoder.hexToBytes(input));
    }

    @Test
    public void convertHexToBytesWithWrongSpacesReturnsCorrectByteArray() {
        String input = " 54 68 69 73 20 69 73 20 61 20 74   65 73 74 ";
        byte[] output = new byte[] { 84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116 };

        assertArrayEquals(output, Decoder.hexToBytes(input));
    }

    @Test
    public void testGetValueByBase64String() {
        String input = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0";

        assertEquals("RSA1_5", Decoder.getValueByBase64String(input, "alg"));
        assertEquals("A192CBC-HS384", Decoder.getValueByBase64String(input, "enc"));
        assertEquals("", Decoder.getValueByBase64String(input, "invalid"));

        String input2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

        assertEquals("HS256", Decoder.getValueByBase64String(input2, "alg"));
        assertEquals("JWT", Decoder.getValueByBase64String(input2, "typ"));
        assertEquals("", Decoder.getValueByBase64String(input2, "enc"));
    }

}
