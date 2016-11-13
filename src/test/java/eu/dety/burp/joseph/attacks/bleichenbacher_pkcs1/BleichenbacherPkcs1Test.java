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
package eu.dety.burp.joseph.attacks.bleichenbacher_pkcs1;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.BurpExtenderCallbacksMock;
import eu.dety.burp.joseph.utilities.JoseParameter;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BleichenbacherPkcs1Test {

    @Test
    public void isSuitableWithJwsPayloadTypeAndDifferentAlgorithmsReturnsTrue() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        BleichenbacherPkcs1Info bleichenbacherPkcs1Info = new BleichenbacherPkcs1Info(callbacks);

        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "HS256"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "HS384"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "HS512"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "RS256"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "RS384"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "RS512"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "ES256"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "ES384"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "ES512"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "PS256"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "PS384"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "PS512"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "none"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, ""));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWS, "INVALID"));
    }

    @Test
    public void isSuitableWithJwePayloadTypeAndDifferentAlgorithmsReturnsTrueOnRsa15Only() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        BleichenbacherPkcs1Info bleichenbacherPkcs1Info = new BleichenbacherPkcs1Info(callbacks);

        assertTrue(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "RSA1_5"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "RSA-OAEP"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "RSA-OAEP-256"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "A128KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "A192KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "A256KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "dir"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A128KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A192KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A256KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "A128GCMKW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "A192GCMKW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "A256GCMKW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS256+A128KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS384+A192KW"));
        assertFalse(bleichenbacherPkcs1Info.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS512+A256KW"));
    }

}