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
package eu.dety.burp.joseph.attacks.invalid_curve;

import burp.IBurpExtenderCallbacks;
import eu.dety.burp.joseph.BurpExtenderCallbacksMock;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.utilities.Converter;
import eu.dety.burp.joseph.utilities.Crypto;
import eu.dety.burp.joseph.utilities.JoseParameter;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECKeySpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Point;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.swing.*;

import java.awt.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

public class InvalidCurveInfoTest {
    private static IBurpExtenderCallbacks callbacks;
    private static InvalidCurveInfo invalidCurveInfo;

    @BeforeClass
    public static void setUp() {
        callbacks = new BurpExtenderCallbacksMock();
        invalidCurveInfo = new InvalidCurveInfo(callbacks);
        JoseParameter parameter = new JoseParameter(
                "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiV0ppY2N2MDAtT1g2dWRPZVdLZmlSaFp6emtvQW5mRzlKT0lEcHJRWXBIOCIsInkiOiJ0QWpCMmk4aHMtN2k2R0xSY2dNVHRDb1BieWJtb1BSV2hTOXFVQmYybGRjIiwiY3J2IjoiUC0yNTYifX0.V-ysNGtp2J0bhBGPBNASvyrJhX4SvLloG4teJsscrlxtr0ErD9rE5w.WkFx8FWePxj9a7vvb_6OJg.Wtuh1S9-XjIuyPYpSIlU-e-toHLA_RBuAF-Ss9ZyH1-SYxIH1SAq1UipYON7LaLkG_P007SJAbUcGrqHjLytaA.u_d-9i17vWVBQeHWZC_H5A",
                JoseParameter.JoseType.JWE);
        // parameter.setDirect("eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiV0ppY2N2MDAtT1g2dWRPZVdLZmlSaFp6emtvQW5mRzlKT0lEcHJRWXBIOCIsInkiOiJ0QWpCMmk4aHMtN2k2R0xSY2dNVHRDb1BieWJtb1BSV2hTOXFVQmYybGRjIiwiY3J2IjoiUC0yNTYifX0.V-ysNGtp2J0bhBGPBNASvyrJhX4SvLloG4teJsscrlxtr0ErD9rE5w.WkFx8FWePxj9a7vvb_6OJg.Wtuh1S9-XjIuyPYpSIlU-e-toHLA_RBuAF-Ss9ZyH1-SYxIH1SAq1UipYON7LaLkG_P007SJAbUcGrqHjLytaA.u_d-9i17vWVBQeHWZC_H5A");
        // parameter.setOriginType(JoseParameter.OriginType.DIRECT);
        invalidCurveInfo.setParameter(parameter);
    }

    @Test
    public void getIdTest() {
        assertEquals("invalid_curve", invalidCurveInfo.getId());
    }

    @Test
    public void getNameTest() {
        assertEquals("Invalid Curve", invalidCurveInfo.getName());
    }

    @Test
    public void getDescriptionTest() {
        assertNotNull(invalidCurveInfo.getDescription());
    }

    @Test
    public void isSuitableTest() {
        JoseParameter.JoseType type = JoseParameter.JoseType.JWE;
        /*
         * String[] algorithms = { "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW*", "ECDH-ES+A256KW*" }; for (String algorithm : algorithms)
         * assertTrue(invalidCurveInfo.isSuitable(type, algorithm));
         */
        assertTrue(invalidCurveInfo.isSuitable(type, null));
    }

    @Test
    public void getPayloadListTest() {
        assertNull(invalidCurveInfo.getPayloadList());
    }

    @Test
    public void getRequestsTest() {
        assertNotNull(invalidCurveInfo.getRequests());
    }

    @Test
    public void getRequestResponseTest() {
        assertNull(invalidCurveInfo.getRequestResponse());
    }

    @Test
    public void getAmaountRequestsTest() {
        assertEquals(0, invalidCurveInfo.getAmountRequests());
    }

    @Test
    public void getExtraUITest() {
        JPanel jp = new JPanel();
        GridBagConstraints gbc = new GridBagConstraints();
        assertTrue(invalidCurveInfo.getExtraUI(jp, gbc));
    }

    @Test
    public void generateValidKeyTest() {
        assertNotNull(invalidCurveInfo.generateValidKey());
    }

    // @After
    // public final static void tearDown() {
    // }

    @Test
    public void generateJWETest() throws AttackPreparationFailedException, NoSuchAlgorithmException {
        invalidCurveInfo.setEcPublicKey((ECPublicKey) invalidCurveInfo.generateValidKey().getPublic());
        IPair<BigInteger, BigInteger> point = invalidCurveInfo.getPointFromECKeyPair(invalidCurveInfo.generateValidKey());
        String[] result = invalidCurveInfo.generateJWE((Point) point, (Point) point, null);
        assertNotNull(result);
    }

    @Test
    public void getComponentsTest() throws NoSuchAlgorithmException, ParseException {
        String pub = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"}";
        Object publicKeyValueJson;
        publicKeyValueJson = new JSONParser().parse(pub);
        ECPublicKey ecPub = Converter.getECPublicKeyByJwk(publicKeyValueJson);
        invalidCurveInfo.setEcPublicKey(ecPub);
        Point jwePoint = new Point(new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
                Base64.decodeInteger("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo".getBytes()),
                Base64.decodeInteger("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0".getBytes()),
                Base64.decodeInteger("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps".getBytes()));
        String partyUInfo = "Alice";
        String partyVInfo = "Bob";
        String plaintext = "";
        byte[][] componentes = invalidCurveInfo.getComponents(jwePoint, jwePoint, partyUInfo, partyVInfo, plaintext, null);
        assertNotNull(componentes);

    }

}
