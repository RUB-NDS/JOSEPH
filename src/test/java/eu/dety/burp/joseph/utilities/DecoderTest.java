/**
 * JOSEPH - JavaScript Object Signing and Encryption Pentesting Helper
 * Copyright (C) 2016 Dennis Detering
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package eu.dety.burp.joseph.utilities;

import static org.junit.Assert.*;
import org.junit.Test;

public class DecoderTest {
    private static final Decoder joseDecoder = new Decoder();

    @Test
    public void getEncodedWithBytesInputReturnsCorrectBase64UrlEncodedString() {
        byte[] input = new byte[] {84, 101, 115, 116, 32, 73, 110, 112, 117, 116};

        assertEquals(joseDecoder.getEncoded(input), "VGVzdCBJbnB1dA");
    }

    @Test
    public void getEncodedWithStringInputReturnsCorrectBase64UrlEncodedString() {
        String input = "Test Input";

        assertEquals(joseDecoder.getEncoded(input), "VGVzdCBJbnB1dA");
    }

    @Test
    public void getDecodedWithBase64UrlStringInputReturnsCorrectDecodedString() {
        String input = "VGVzdCBJbnB1dA";

        assertEquals(joseDecoder.getDecoded(input), "Test Input");
    }

    @Test
    public void getDecodedGetEncodedWithStringInputReturnsSameString() {
        String input = "Test Input";

        assertEquals(joseDecoder.getDecoded(joseDecoder.getEncoded(input)), "Test Input");
    }

    @Test
    public void getComponentsWithJwtInputReturnsStringArrayWithThreeComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        String[] expected = new String[] {"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzb21lIjoicGF5bG9hZCJ9", "4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg"};

        assertArrayEquals(joseDecoder.getComponents(token), expected);
    }



}
