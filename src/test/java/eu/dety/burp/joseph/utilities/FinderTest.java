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

import org.junit.Ignore;
import org.junit.Test;

public class FinderTest {
    private static final Finder finder = new Finder();

    @Test
    public void testJwtHs() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertTrue(finder.checkJWTPattern(token));
    }

    @Test
    public void testJwtRs() {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.kICC_hdjv5FXzfiU-2F4QDMb9N71L_fiUlgwk_cwPUWG3Fn6FweKG4jSlbgVJGHTbp-sF34n79TiLbjK1IP31KS3rxWaHzO0enB6QZe9nktzSLx2H-rnyYtRZZ0o4KfaCh03TuhMdBtL2UpekkyjTwBsb1hULZPSt2xx_gsY5GwpK3XeaqpoMxFGNopgpg7IQ1C0QbQHDNPzld-PqsnPIIOt6VG0f4LWFyWJOlpz0ZXy06VXjFY3ALix9GVUbRJQ4sDHg5FK7gl2P1ovow1b7JysTgl_HeD8CpbIUUy5Gxa8nIdPmb4eKoG3dM-J_AaxewqFuvHMfqSey_cIdFsxtw";

        assertTrue(finder.checkJWTPattern(token));
    }

    @Test
    public void testInvalidHeader() {
        String token = "SW52YWxpZCBIZWFkZXI.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";

        assertFalse(finder.checkJWTPattern(token));
    }

    @Test
    public void testTooFewComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9";

        assertFalse(finder.checkJWTPattern(token));
    }

    /* TODO: Implement if different checker for JWT and JWE exist */
    @Ignore
    public void testInvalidPayload() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SW52YWxpZCBQYXlsb2Fk.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        assertFalse(finder.checkJWTPattern(token));
    }

    @Ignore
    public void testTooManyComponents() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        assertFalse(finder.checkJWTPattern(token));
    }
}
