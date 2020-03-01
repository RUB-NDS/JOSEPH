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

import org.bouncycastle.jce.interfaces.ECPrivateKey;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static org.junit.Assert.*;

public class ChineseRemainderTest {
    ChineseRemainder cr;

    @Before
    public void setUp() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(ecGenSpec, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        BigInteger d = new BigInteger("22040");
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(((ECPrivateKey) pair.getPrivate()).getParameters().getG().multiply(d),
                ((ECPrivateKey) pair.getPrivate()).getParameters());
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        ECPublicKey ecPublicKey = (ECPublicKey) kf.generatePublic(ecPublicKeySpec);
        cr = ChineseRemainder.startInstance(ecPublicKey, ((ECPrivateKey) pair.getPrivate()).getParameters());
    }

    @Test
    public void getPowerSetTest() {
        Point x1 = new Point(new BigInteger("5"), new BigInteger("3"), null, null);
        Point x2 = new Point(new BigInteger("5"), new BigInteger("2"), null, null);
        Point x3 = new Point(new BigInteger("7"), new BigInteger("0"), null, null);
        Point x4 = new Point(new BigInteger("7"), new BigInteger("4"), null, null);
        Point x5 = new Point(new BigInteger("3"), new BigInteger("2"), null, null);
        Point x6 = new Point(new BigInteger("11"), new BigInteger("4"), null, null);
        Point x7 = new Point(new BigInteger("3"), new BigInteger("1"), null, null);
        Point x8 = new Point(new BigInteger("11"), new BigInteger("6"), null, null);
        cr.addPoint(x1);
        cr.addPoint(x2);
        cr.addPoint(x3);
        cr.addPoint(x4);
        cr.addPoint(x5);
        cr.addPoint(x6);
        cr.addPoint(x7);
        cr.addPoint(x8);
    }
}
