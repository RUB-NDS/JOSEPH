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

import org.junit.Test;

import static org.junit.Assert.*;

public class FinderTest {

    @Test
    public void checkJwsPatternWithValidHmacJwsInputReturnsTrue() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertTrue(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithValidRsaJwsInputReturnsTrue() {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.kICC_hdjv5FXzfiU-2F4QDMb9N71L_fiUlgwk_cwPUWG3Fn6FweKG4jSlbgVJGHTbp-sF34n79TiLbjK1IP31KS3rxWaHzO0enB6QZe9nktzSLx2H-rnyYtRZZ0o4KfaCh03TuhMdBtL2UpekkyjTwBsb1hULZPSt2xx_gsY5GwpK3XeaqpoMxFGNopgpg7IQ1C0QbQHDNPzld-PqsnPIIOt6VG0f4LWFyWJOlpz0ZXy06VXjFY3ALix9GVUbRJQ4sDHg5FK7gl2P1ovow1b7JysTgl_HeD8CpbIUUy5Gxa8nIdPmb4eKoG3dM-J_AaxewqFuvHMfqSey_cIdFsxtw";

        assertTrue(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithInvalidEncodedHeaderJwsInputReturnsFalse() {
        String token = "SW52YWxpZCBIZWFkZXI.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertFalse(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithTwoComponentJwsWithEndingDotInputReturnsTrue() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.";

        assertTrue(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithTwoComponentJwsWithoutEndingDotInputReturnsFalse() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9";

        assertFalse(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithEmptyInputReturnsFalse() {
        String token = "";

        assertFalse(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithNullInputReturnsFalse() {
        String token = null;

        assertFalse(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkAuthorizationHeaderWithValidHmacJwsPatternReturnsJwsValue() {
        String token = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", Finder.getJoseValue(token));
    }

    @Test
    public void checkAuthorizationHeaderWithValidRsaJwsPatternReturnsJwsValue() {
        String token = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.kICC_hdjv5FXzfiU-2F4QDMb9N71L_fiUlgwk_cwPUWG3Fn6FweKG4jSlbgVJGHTbp-sF34n79TiLbjK1IP31KS3rxWaHzO0enB6QZe9nktzSLx2H-rnyYtRZZ0o4KfaCh03TuhMdBtL2UpekkyjTwBsb1hULZPSt2xx_gsY5GwpK3XeaqpoMxFGNopgpg7IQ1C0QbQHDNPzld-PqsnPIIOt6VG0f4LWFyWJOlpz0ZXy06VXjFY3ALix9GVUbRJQ4sDHg5FK7gl2P1ovow1b7JysTgl_HeD8CpbIUUy5Gxa8nIdPmb4eKoG3dM-J_AaxewqFuvHMfqSey_cIdFsxtw";

        assertEquals(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.kICC_hdjv5FXzfiU-2F4QDMb9N71L_fiUlgwk_cwPUWG3Fn6FweKG4jSlbgVJGHTbp-sF34n79TiLbjK1IP31KS3rxWaHzO0enB6QZe9nktzSLx2H-rnyYtRZZ0o4KfaCh03TuhMdBtL2UpekkyjTwBsb1hULZPSt2xx_gsY5GwpK3XeaqpoMxFGNopgpg7IQ1C0QbQHDNPzld-PqsnPIIOt6VG0f4LWFyWJOlpz0ZXy06VXjFY3ALix9GVUbRJQ4sDHg5FK7gl2P1ovow1b7JysTgl_HeD8CpbIUUy5Gxa8nIdPmb4eKoG3dM-J_AaxewqFuvHMfqSey_cIdFsxtw",
                Finder.getJoseValue(token));
    }

    @Test
    public void checkJwsPatternWithInvalidEncodedHeaderJwsInputReturnsNull() {
        String token = "SW52YWxpZCBIZWFkZXI.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertNull(Finder.getJoseValue(token));
    }

    @Test
    public void checkCustomHeaderWithValidHmacJwsPatternReturnsJwsValue() {
        String token = "X-JWT-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", Finder.getJoseValue(token));
    }

    @Test
    public void checkJwsPatternWithMoreComponentsReturnsCorrectJwsValue() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertEquals(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg",
                Finder.getJoseValue(token));
    }

    @Test
    public void checkJwsPatternWithInvalidEncodedPayloadJwsInputReturnsFalse() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SW52YWxpZCBQYXlsb2Fk.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        assertFalse(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwsPatternWithFourComponentJwsInputReturnsFalse() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        assertFalse(Finder.checkJwsPattern(token));
    }

    @Test
    public void checkJwePatternWithValidRsaJweInputReturnsTrue() {
        String token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.MeAxi3xwgEt4aVTHVCWtijYCKAzu4AWbu7WdtqzgxhVbBbXrW_mqo3DGXtNFeRTEEweGDf5g5-2osbFUyYIJsRXj8tyE5HRMzbHBGrimKTTk7HTLv1KSwnKXVCGjy6ROxXjAjKVwGU5MDwP28XwhGAlS6fCYx_nIk-J7wf9YV1NDtDxk9F-s10J9BHJ27-l1M1HIVv7McWw94837UY4fM63BLDAJ70KbQvh_LF8RMdI7F2WXe-vTEcwFmicDi9Q6yvRzbYUhL1I19K4PHs9gTHtM-icRbJzPJvm0HKv0gclsXcsQtZgHNFTm3uLYbV5azYu5g5a5Iey-H1dvtpfbIQ.cwy_JXzA6_ZrdDETzYuPbw.o0qbcF7WeGansYSyRR3nZ82MRVoGnyVt4MdZZ00IgGw.vDZidX32xbA7uEUa7GMyiA";

        assertTrue(Finder.checkJwePattern(token));
    }

    @Test
    public void checkJwePatternWithInvalidEncodedHeaderJweInputReturnsFalse() {
        String token = "SW52YWxpZCBIZWFkZXI.MeAxi3xwgEt4aVTHVCWtijYCKAzu4AWbu7WdtqzgxhVbBbXrW_mqo3DGXtNFeRTEEweGDf5g5-2osbFUyYIJsRXj8tyE5HRMzbHBGrimKTTk7HTLv1KSwnKXVCGjy6ROxXjAjKVwGU5MDwP28XwhGAlS6fCYx_nIk-J7wf9YV1NDtDxk9F-s10J9BHJ27-l1M1HIVv7McWw94837UY4fM63BLDAJ70KbQvh_LF8RMdI7F2WXe-vTEcwFmicDi9Q6yvRzbYUhL1I19K4PHs9gTHtM-icRbJzPJvm0HKv0gclsXcsQtZgHNFTm3uLYbV5azYu5g5a5Iey-H1dvtpfbIQ.cwy_JXzA6_ZrdDETzYuPbw.o0qbcF7WeGansYSyRR3nZ82MRVoGnyVt4MdZZ00IgGw.vDZidX32xbA7uEUa7GMyiA";

        assertFalse(Finder.checkJwePattern(token));
    }

    @Test
    public void checkJwePatternWithFourComponentJweInputReturnsFalse() {
        String token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.MeAxi3xwgEt4aVTHVCWtijYCKAzu4AWbu7WdtqzgxhVbBbXrW_mqo3DGXtNFeRTEEweGDf5g5-2osbFUyYIJsRXj8tyE5HRMzbHBGrimKTTk7HTLv1KSwnKXVCGjy6ROxXjAjKVwGU5MDwP28XwhGAlS6fCYx_nIk-J7wf9YV1NDtDxk9F-s10J9BHJ27-l1M1HIVv7McWw94837UY4fM63BLDAJ70KbQvh_LF8RMdI7F2WXe-vTEcwFmicDi9Q6yvRzbYUhL1I19K4PHs9gTHtM-icRbJzPJvm0HKv0gclsXcsQtZgHNFTm3uLYbV5azYu5g5a5Iey-H1dvtpfbIQ.cwy_JXzA6_ZrdDETzYuPbw.o0qbcF7WeGansYSyRR3nZ82MRVoGnyVt4MdZZ00IgGw";

        assertFalse(Finder.checkJwePattern(token));
    }

    @Test
    public void checkJwePatternWithEmptyInputReturnsFalse() {
        String token = "";

        assertFalse(Finder.checkJwePattern(token));
    }

    @Test
    public void checkJwePatternWithNullInputReturnsFalse() {
        String token = null;

        assertFalse(Finder.checkJwePattern(token));
    }

    @Test
    public void checkJwePatternWithSixComponentJweInputReturnsFalse() {
        String token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.MeAxi3xwgEt4aVTHVCWtijYCKAzu4AWbu7WdtqzgxhVbBbXrW_mqo3DGXtNFeRTEEweGDf5g5-2osbFUyYIJsRXj8tyE5HRMzbHBGrimKTTk7HTLv1KSwnKXVCGjy6ROxXjAjKVwGU5MDwP28XwhGAlS6fCYx_nIk-J7wf9YV1NDtDxk9F-s10J9BHJ27-l1M1HIVv7McWw94837UY4fM63BLDAJ70KbQvh_LF8RMdI7F2WXe-vTEcwFmicDi9Q6yvRzbYUhL1I19K4PHs9gTHtM-icRbJzPJvm0HKv0gclsXcsQtZgHNFTm3uLYbV5azYu5g5a5Iab-H1dvtpfbIQ.cwy_JXzA6_ZrdDETzYuPbw.o0qbcF7WeGansYSyRR3nZ82MRVoGnyVt4MdZZ00IgGw.vDZidX32xbA7uEUa7GMyiA.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

        assertFalse(Finder.checkJwePattern(token));
    }

}
