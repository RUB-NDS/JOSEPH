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

import burp.IParameter;
import eu.dety.burp.joseph.BurpParameterMock;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
    public void checkGetValueOnJoseParameterWithHeaderInputReturnsCorrectValueString() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(header, JoseParameter.JoseType.JWS);

        assertEquals("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg",
                joseParameter.getValue());
    }

    @Test
    public void checkGetJoseValueOnJoseParameterWithHeaderInputReturnsCorrectJoseValueString() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(header, JoseParameter.JoseType.JWS);

        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", joseParameter.getJoseValue());
    }

    @Test
    public void checkJoseParameterCorrectlyInitializesWithParameterInput() {
        BurpParameterMock parameter = new BurpParameterMock("token",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", IParameter.PARAM_URL);
        JoseParameter joseParameter = new JoseParameter(parameter, JoseParameter.JoseType.JWS);

        assertNotNull(joseParameter);
        assertEquals(JoseParameter.OriginType.PARAMETER, joseParameter.getOriginType());
    }

    @Test
    public void checkGetNameOnJoseParameterWithParameterInputReturnsCorrectNameString() {
        BurpParameterMock parameter = new BurpParameterMock("token",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", IParameter.PARAM_URL);
        JoseParameter joseParameter = new JoseParameter(parameter, JoseParameter.JoseType.JWS);

        assertEquals("token", joseParameter.getName());
    }

    @Test
    public void checkGetValueOnJoseParameterWithParameterInputReturnsCorrectValueString() {
        BurpParameterMock parameter = new BurpParameterMock("token",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", IParameter.PARAM_URL);
        JoseParameter joseParameter = new JoseParameter(parameter, JoseParameter.JoseType.JWS);

        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", joseParameter.getValue());
    }

    @Test
    public void checkGetJoseValueOnJoseParameterWithParameterInputReturnsCorrectJoseValueString() {
        BurpParameterMock parameter = new BurpParameterMock("token",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", IParameter.PARAM_URL);
        JoseParameter joseParameter = new JoseParameter(parameter, JoseParameter.JoseType.JWS);

        assertEquals("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", joseParameter.getJoseValue());
    }

    @Test
    public void checkJoseParameterCorrectlyInitializesWithBodyParameterInput() {
        BurpParameterMock parameter = new BurpParameterMock("post-parameter",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", IParameter.PARAM_BODY);
        JoseParameter joseParameter = new JoseParameter(parameter, JoseParameter.JoseType.JWS);

        assertNotNull(joseParameter);
        assertEquals(JoseParameter.OriginType.PARAMETER, joseParameter.getOriginType());
    }

    @Test
    public void checkJoseParameterCorrectlyInitializesWithCookieParameterInput() {
        BurpParameterMock parameter = new BurpParameterMock("cookie-token",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg", IParameter.PARAM_COOKIE);
        JoseParameter joseParameter = new JoseParameter(parameter, JoseParameter.JoseType.JWS);

        assertNotNull(joseParameter);
        assertEquals(JoseParameter.OriginType.PARAMETER, joseParameter.getOriginType());
    }

    @Test
    public void checkJoseParameterCorrectlyInitializesWithDirectJwtInput() throws InvalidJoseValueException {
        String input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg";
        JoseParameter joseParameter = new JoseParameter(input);

        assertNotNull(joseParameter);
        assertEquals(JoseParameter.OriginType.DIRECT, joseParameter.getOriginType());
        assertEquals(JoseParameter.JoseType.JWS, joseParameter.getJoseType());
    }

    @Test
    public void checkJoseParameterCorrectlyInitializesWithDirectJweInput() throws InvalidJoseValueException {
        String input = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ZUv6KX2ACkbX4vxmmRP_klq7vBhkD8rezLWM3o2Z14iptapIL39t1hMgKyqFXHXHsanzGK_ebPEr4ksrrCW6wbMixaPureAjdfvozBP_Yfy7ZLyMXx3AORPD5p6yvwtWY3HILc2Y2v0JUggIhZw1GVumoOc1pbZUn5WRVsnkzI8.Oi4EPrRuKona7h1QSXJdVA.s5JN_1NXdGcjhKC1qeLBgw.T8m2q4Bttn40Juo86nLODw";
        JoseParameter joseParameter = new JoseParameter(input);

        assertNotNull(joseParameter);
        assertEquals(JoseParameter.OriginType.DIRECT, joseParameter.getOriginType());
        assertEquals(JoseParameter.JoseType.JWE, joseParameter.getJoseType());
    }

    @Test(expected = InvalidJoseValueException.class)
    public void checkJoseParameterCorrectlyInitializesWithWrongDirectInputThrowsException() throws InvalidJoseValueException {
        String input = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ZUv6KX2ACkbX4vxmmRP_klq7vBhkD8rezLWM3o2Z14iptapIL39t1hMgKyqFXHXHsanzGK_ebPEr4ksrrCW6wbMixaPureAjdfvozBP_Yfy7ZLyMXx3AORPD5p6yvwtWY3HILc2Y2v0JUggIhZw1GVumoOc1pbZUn5WRVsnkzI8.Oi4EPrRuKona7h1QSXJdVA.s5JN_1NXdGcjhKC1qeLBgw";
        new JoseParameter(input);
    }

    @Test(expected = InvalidJoseValueException.class)
    public void checkJoseParameterCorrectlyInitializesWithEmptyDirectInputThrowsException() throws InvalidJoseValueException {
        String input = "";
        new JoseParameter(input);
    }

    @Test(expected = InvalidJoseValueException.class)
    public void checkJoseParameterCorrectlyInitializesWithNullDirectInputThrowsException() throws InvalidJoseValueException {
        String input = null;
        new JoseParameter(input);
    }

}
