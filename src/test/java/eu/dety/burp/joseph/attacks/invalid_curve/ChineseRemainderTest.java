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
        // List<List<Point>> lists = cr.getCombinatedLists();
        // for (List<Point> list : lists) {
        // System.out.println(list);
        // }
    }

    // @Test
    // public void calculateCRTest() {
    // Point x1 = new Point(new BigInteger("9"), new BigInteger("1"), null, null);
    // Point x2 = new Point(new BigInteger("8"), new BigInteger("2"), null, null);
    // Point x3 = new Point(new BigInteger("7"), new BigInteger("0"), null, null);
    // Point x4 = new Point(new BigInteger("13"), new BigInteger("8"), null, null);
    // Point x5 = new Point(new BigInteger("17"), new BigInteger("12"), null, null);
    // Point x6 = new Point(new BigInteger("5"), new BigInteger("4"), null, null);
    // cr.addPoint(x1);
    // cr.addPoint(x2);
    // cr.addPoint(x3);
    // cr.addPoint(x4);
    // cr.addPoint(x5);
    // cr.addPoint(x6);
    // BigInteger expected = new BigInteger("446194");
    // cr.calculateCR();
    // assertEquals(expected, cr.getCalculated());
    // }

    // @Test
    // public void squareCRTest() {
    // Point x1 = new Point(new BigInteger("9"), new BigInteger("1"), null, null);
    // Point x2 = new Point(new BigInteger("8"), new BigInteger("2"), null, null);
    // Point x3 = new Point(new BigInteger("7"), new BigInteger("0"), null, null);
    // Point x4 = new Point(new BigInteger("13"), new BigInteger("8"), null, null);
    // Point x5 = new Point(new BigInteger("17"), new BigInteger("12"), null, null);
    // Point x6 = new Point(new BigInteger("5"), new BigInteger("4"), null, null);
    // cr.addPoint(x1);
    // cr.addPoint(x2);
    // cr.addPoint(x3);
    // cr.addPoint(x4);
    // cr.addPoint(x5);
    // cr.addPoint(x6);
    // BigInteger expected = new BigInteger("446194");
    // cr.squaredCR();
    // // cr.calculateSquaredCR();
    // assertEquals(new BigInteger("556920"), cr.getModulus());
    // // assertEquals(expected, cr.getCalculated());
    // }
    // @Test
    // public void isprtTest() {
    // BigInteger expected = new BigInteger("3");
    // BigInteger actual = cr.isqrt(new BigInteger("10"));
    // assertEquals(expected, actual);
    // }

    // @Test
    // public void proofResultTest() {
    // Point x4 = new Point(new BigInteger("179"), new BigInteger("23"), null, null);
    // Point x5 = new Point(new BigInteger("2447"), new BigInteger("17"), null, null);
    // cr.addPoint(x4);
    // cr.addPoint(x5);
    // cr.calculateCR();
    // assertTrue(cr.checkResult());
    // }

    // @Test
    // public void addPointTest() {
    // Point x1 = new Point(new BigInteger("9"), new BigInteger("1"), null, null);
    // Point x2 = new Point(new BigInteger("9"), new BigInteger("2"), null, null);
    // Point x3 = new Point(new BigInteger("7"), new BigInteger("0"), null, null);
    // cr.addPoint(x1);
    // cr.addPoint(x2);
    // cr.addPoint(x3);
    // cr.calculateCR();
    // String actual = cr.getCalculated().toString();
    // String expected = "28";
    // // assertEquals(expected, actual);
    // }
}
