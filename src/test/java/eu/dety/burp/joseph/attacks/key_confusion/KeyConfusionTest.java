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
package eu.dety.burp.joseph.attacks.key_confusion;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.BurpExtenderCallbacksMock;
import eu.dety.burp.joseph.utilities.Converter;
import eu.dety.burp.joseph.utilities.JoseParameter;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.List;

import static org.junit.Assert.*;

public class KeyConfusionTest {

    private Object publickKeyValueJson = new JSONParser()
            .parse("{ \"kty\": \"RSA\",\n"
                    + "\"use\": \"sig\",\n"
                    + "\"n\": \"AJHguTrOdP5WHE0LRn1xNh3wBX6yYC4JfsPPXYhUkcSJhrVkbUlimx35GWhAj7lFLqQOJipLiQqRTds2Gtgz3ZYjk_5PLveY3Y_-89PPFUj1oBkZ6toCdvlN8PWBbrxfhl2NxI8jYUU2nrJAx_PoyGHtnye9GseYbhH8On4kGsmt\",\n"
                    + "\"e\": \"AQAB\" }");

    public KeyConfusionTest() throws ParseException {
    }

    @Test
    public void isSuitableWithJwsPayloadTypeAndDifferentAlgorithmsReturnsTrue() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "HS256"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "HS384"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "HS512"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "RS256"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "RS384"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "RS512"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "ES256"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "ES384"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "ES512"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "PS256"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "PS384"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "PS512"));
        assertTrue(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWS, "none"));
    }

    @Test
    public void isSuitableWithJwePayloadTypeAndDifferentAlgorithmsReturnsFalse() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "RSA1_5"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "RSA-OAEP"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "RSA-OAEP-256"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "A128KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "A192KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "A256KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "dir"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A128KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A192KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "ECDH-ES+A256KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "A128GCMKW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "A192GCMKW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "A256GCMKW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS256+A128KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS384+A192KW"));
        assertFalse(keyConfusionInfo.isSuitable(JoseParameter.JoseType.JWE, "PBES2-HS512+A256KW"));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForOrigPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.ORIGINAL, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForOrigNoHeadFootPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.ORIGINAL_NO_HEADER_FOOTER, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForOrigNoLfPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "-----BEGIN PUBLIC KEY-----" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB" + "-----END PUBLIC KEY-----";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.ORIGINAL_NO_LF, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForOrigNoHeadFootLfPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.ORIGINAL_NO_HEADER_FOOTER_LF, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForOriginalAdditionalLfayload() throws UnsupportedEncodingException {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.ORIGINAL_ADDITIONAL_LF, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs1Payload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "MIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n" + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n"
                + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n" + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n"
                + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n" + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n"
                + "swIDAQAB";

        String input = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n"
                + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n" + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n"
                + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n" + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n"
                + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n" + "swIDAQAB";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS1, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs1NoHeadFootPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "MIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n" + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n"
                + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n" + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n"
                + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n" + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n"
                + "swIDAQAB";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n"
                + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n" + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n"
                + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n" + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n"
                + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n" + "swIDAQAB" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS1_NO_HEADER_FOOTER, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs1NoHeadFootLfPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "MIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D" + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ"
                + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ" + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9"
                + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa" + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs"
                + "swIDAQAB";

        String input = "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n"
                + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n" + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n"
                + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n" + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n"
                + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n" + "swIDAQAB" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS1_NO_HEADER_FOOTER_LF, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs1NoLfPayload() {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        String expected = "MIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D" + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ"
                + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ" + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9"
                + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa" + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs"
                + "swIDAQAB" + "-----END PUBLIC KEY-----";

        String input = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n"
                + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n" + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n"
                + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n" + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n"
                + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n" + "swIDAQAB" + "-----END PUBLIC KEY-----\n";

        assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS1_NO_LF, input));
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs8WithHeadFootPayload() throws UnsupportedEncodingException {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        List<PublicKey> publicKeys = Converter.getRsaPublicKeysByJwk(publickKeyValueJson);

        String expected = "-----BEGIN PUBLIC KEY-----" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB" + "-----END PUBLIC KEY-----";

        for (PublicKey publicKey : publicKeys) {
            assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS8_WITH_HEADER_FOOTER, publicKey));
        }
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs8Payload() throws UnsupportedEncodingException {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        List<PublicKey> publicKeys = Converter.getRsaPublicKeysByJwk(publickKeyValueJson);

        String expected = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB";

        for (PublicKey publicKey : publicKeys) {
            assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS8, publicKey));
        }
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs8WithLfPayload() throws UnsupportedEncodingException {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        List<PublicKey> publicKeys = Converter.getRsaPublicKeysByJwk(publickKeyValueJson);

        String expected = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n";

        for (PublicKey publicKey : publicKeys) {
            assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS8_WITH_LF, publicKey));
        }
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs8WithLfHeadFootPayload() throws UnsupportedEncodingException {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        List<PublicKey> publicKeys = Converter.getRsaPublicKeysByJwk(publickKeyValueJson);

        String expected = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----";

        for (PublicKey publicKey : publicKeys) {
            assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS8_WITH_HEADER_FOOTER_LF, publicKey));
        }
    }

    @Test
    public void checktransformKeyByPayloadReturnsCorrectValueForPkcs8WithLfHeadFootEndLfPayload() throws UnsupportedEncodingException {
        IBurpExtenderCallbacks callbacks = new BurpExtenderCallbacksMock();

        KeyConfusionInfo keyConfusionInfo = new KeyConfusionInfo(callbacks);

        List<PublicKey> publicKeys = Converter.getRsaPublicKeysByJwk(publickKeyValueJson);

        String expected = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCR4Lk6znT+VhxNC0Z9cTYd8AV+\n"
                + "smAuCX7Dz12IVJHEiYa1ZG1JYpsd+RloQI+5RS6kDiYqS4kKkU3bNhrYM92WI5P+\n" + "Ty73mN2P/vPTzxVI9aAZGeraAnb5TfD1gW68X4ZdjcSPI2FFNp6yQMfz6Mhh7Z8n\n"
                + "vRrHmG4R/Dp+JBrJrQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        for (PublicKey publicKey : publicKeys) {
            assertEquals(expected, keyConfusionInfo.transformKeyByPayload(KeyConfusionInfo.PayloadType.PKCS8_WITH_HEADER_FOOTER_LF_ENDING_LF, publicKey));
        }
    }

}
