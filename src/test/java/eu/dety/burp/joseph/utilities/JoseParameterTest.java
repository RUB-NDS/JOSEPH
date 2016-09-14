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

public class JoseParameterTest {

    @Test
    public void checkJoseParameterCorrectlyInitializesWithHeaderInput() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(header, JoseParameter.JoseType.JWS);

        assertNotNull(joseParameter);
        assertEquals(JoseParameter.OriginType.HEADER, joseParameter.getOriginType());
    }

    @Test
    public void checkGetNameOnJoseParameterWithHeaderInputReturnsCorrectNameString() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(header, JoseParameter.JoseType.JWS);

        assertEquals("Authorization", joseParameter.getName());
    }

    @Test
    public void checkGetValueOnJoseParameterWithHeaderInputReturnsCorrectNameString() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(header, JoseParameter.JoseType.JWS);

        assertEquals("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", joseParameter.getValue());
    }

    @Test
    public void checkGetJoseValueOnJoseParameterWithHeaderInputReturnsCorrectNameString() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(header, JoseParameter.JoseType.JWS);

        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", joseParameter.getJoseValue());
    }


}
