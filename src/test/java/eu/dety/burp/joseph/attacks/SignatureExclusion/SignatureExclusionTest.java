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
package eu.dety.burp.joseph.attacks.SignatureExclusion;

import static org.junit.Assert.*;

import burp.*;
import eu.dety.burp.joseph.BurpExtenderCallbacksMock;
import org.junit.Test;

import java.util.HashMap;


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

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.payloadType.LOWERCASE, header, payload));
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

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.payloadType.UPPERCASE, header, payload));
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

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.payloadType.CAPITALIZED, header, payload));
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

        assertEquals(expected, signatureExclusion.updateValuesByPayload(SignatureExclusionInfo.payloadType.MIXED, header, payload));
    }

}