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
package eu.dety.burp.joseph.attacks.signature_exclusion;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.BurpExtenderCallbacksMock;
import eu.dety.burp.joseph.utilities.JoseParameter;
import org.junit.Test;

import java.util.HashMap;

import static org.junit.Assert.*;

public class SignatureExclusionTest {

    @Test
    public void checkLowercasePayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"some\":\"payload\"}";

        HashMap<String, String> expected = new HashMap<>();

        expected.put("header", "{\"alg\":\"none\",\"typ\":\"JWT\"}");
        expected.put("payload", payload);
        expected.put("signature", "");

        SignatureExclusionInfo signatureExclusion = new SignatureExclusionInfo(callbacks);

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.PayloadType.LOWERCASE, header, payload, "SomeSignature"));
    }

    @Test
    public void checkUppercasePayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"some\":\"payload\"}";

        HashMap<String, String> expected = new HashMap<>();

        expected.put("header", "{\"alg\":\"NONE\",\"typ\":\"JWT\"}");
        expected.put("payload", payload);
        expected.put("signature", "");

        SignatureExclusionInfo signatureExclusion = new SignatureExclusionInfo(callbacks);

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.PayloadType.UPPERCASE, header, payload, "SomeSignature"));
    }

    @Test
    public void checkCapitalizedPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"some\":\"payload\"}";

        HashMap<String, String> expected = new HashMap<>();

        expected.put("header", "{\"alg\":\"None\",\"typ\":\"JWT\"}");
        expected.put("payload", payload);
        expected.put("signature", "");

        SignatureExclusionInfo signatureExclusion = new SignatureExclusionInfo(callbacks);

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.PayloadType.CAPITALIZED, header, payload, "SomeSignature"));
    }

    @Test
    public void checkMixedPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"some\":\"payload\"}";

        HashMap<String, String> expected = new HashMap<>();

        expected.put("header", "{\"alg\":\"nOnE\",\"typ\":\"JWT\"}");
        expected.put("payload", payload);
        expected.put("signature", "");

        SignatureExclusionInfo signatureExclusion = new SignatureExclusionInfo(callbacks);

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.PayloadType.MIXED, header, payload, "SomeSignature"));
    }

    @Test
    public void isSuitableWithJwsPayloadTypeAndDifferentAlgorithmsReturnsTrue() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        SignatureExclusionInfo signatureExclusion = new SignatureExclusionInfo(callbacks);

        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "HS256"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "HS384"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "HS512"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "RS256"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "RS384"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "RS512"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "ES256"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "ES384"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "ES512"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "PS256"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "PS384"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "PS512"));
        assertTrue(signatureExclusion.isSuitable(JoseParameter.JoseType.JWS, "none"));
    }

    @Test
    public void isSuitableWithJwePayloadTypeAndDifferentAlgorithmsReturnsFalse() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        SignatureExclusionInfo signatureExclusion = new SignatureExclusionInfo(callbacks);

        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "RSA1_5"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "RSA-OAEP"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "RSA-OAEP-256"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "A128KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "A192KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "A256KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "dir"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A128KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A192KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A256KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "A128GCMKW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "A192GCMKW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "A256GCMKW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS256+A128KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS384+A192KW"));
        assertFalse(signatureExclusion.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS512+A256KW"));
    }

}