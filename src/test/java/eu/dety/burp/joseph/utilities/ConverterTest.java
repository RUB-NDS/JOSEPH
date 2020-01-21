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

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import org.junit.Test;

import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.*;

public class ConverterTest {

    @Test
    public void getRsaPublicKeyWithSingleRsaJwkInputReturnsListWithSingleRsaPublicKeyObject() throws NoSuchAlgorithmException, InvalidKeySpecException,
            ParseException {
        Object jwk = new JSONParser()
                .parse("{\"kty\": \"RSA\", \"use\": \"sig\", \"n\": \"AK9LhraAG8Tz55FnLk99Q1V-rJEAS7PhXcaXK5z4tw0IOWVXVHKf7xXibbPRwQVIyF4YUaoanmrkzUa0aU-oWXGdBsBmo4CIhj8jcY5YZFtZF7ynov_3a-8-dQNcfjc6_1U6bBw95bsP6C-oJhaXmX2fnAuVpcK0BjkQ3zoI7SGikTLGwclPJ1WsvTo2pX3HR6QCc1puvDjaO3gBA0mn_S6q3TL6mOqYDIeD3b6aklNbobHe1QSm1rRLO7I-j7B-qiAGb_gGLTRndBc4ZI-sWkwQGOkZeEugJukgspmWAmFYd821RXQ9M8egqCYsVM7FsEm_raKvSG2ehxFo7ZSVbLM\", \"e\": \"AQAB\"}");

        BigInteger modulus = new BigInteger(
                "22128946737323913239210052479333027707901510060102775675830991813349418659538199300647898430584144500806059458278321518777044762899512296866600872394644380219013320495156971514431190023600729602211122577883306928327035481763181383360484196857466673122026840292263234856687762092039930273840883706411057986999291723263528956058054902470342623926525220419403492184749748080083440782860930153041629788053392850350190345701856884676367792841834106393147716901597512639433053628947682648446566660847625123370647049602729290059736582541200917525808306486312868092094709254446973240693245640735124383753810943940731642145971");
        BigInteger publicExponent = new BigInteger("65537");
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        List<PublicKey> publicKeyList = Converter.getRsaPublicKeysByJwk(jwk);

        assertNotNull(publicKeyList);
        assertEquals(1, publicKeyList.size());
        assertEquals(publicKey, publicKeyList.get(0));
    }

    @Test
    public void getRsaPublicKeyWithSingleEcJwkInputReturnsEmptyList() throws ParseException {
        Object jwk = new JSONParser()
                .parse("{\"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", \"use\":\"enc\", \"kid\":\"1\"}");

        List<PublicKey> publicKeyList = Converter.getRsaPublicKeysByJwk(jwk);

        assertNotNull(publicKeyList);
        assertEquals(new ArrayList<PublicKey>(), publicKeyList);
    }

    @Test
    public void getRsaPublicKeyWithTwoKeysRsaAndEcJwkInputReturnsListWithSingleRsaPublicKeyObject() throws NoSuchAlgorithmException, InvalidKeySpecException,
            ParseException {
        Object jwk = new JSONParser()
                .parse("{\"keys\":[{\"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", \"use\":\"enc\", \"kid\":\"1\"},{\"kty\":\"RSA\", \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2 QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\", \"e\":\"AQAB\", \"alg\":\"RS256\", \"kid\":\"2011-04-29\"}]}");

        BigInteger modulus = new BigInteger(
                "-5682458471133998388349435224633069349339468533284902336027705964449388702650944577143355769222747143645802928997396746788844516020279137866835783191591333722847996520065852710220990368127004199808401899736680560956431068787853232744544770599290862357208116339307372204787434279492353211428856678472586090071739438019744959023980640454937307928948909285462577350157199294652794553602056459172956409144930859767392952162694193223130644537748426311422152249961861449835863678305650703998634078098161038037616498189346650489296709705191330089861202606165927388552774443778601636463150652207936779357119888256103014675837");
        BigInteger publicExponent = new BigInteger("65537");
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        List<PublicKey> publicKeyList = Converter.getRsaPublicKeysByJwk(jwk);

        assertNotNull(publicKeyList);
        assertEquals(publicKeyList.size(), 1);
        assertEquals(publicKey, publicKeyList.get(0));
    }

    @Test
    public void getRsaPublicKeyWithTwoRsaJwkInputReturnsListWithTwoRsaPublicKeyObjects() throws NoSuchAlgorithmException, InvalidKeySpecException,
            ParseException {
        Object jwk = new JSONParser()
                .parse("{\"keys\":[{ \"kty\": \"RSA\",\"use\": \"sig\",\"n\": \"AK9LhraAG8Tz55FnLk99Q1V-rJEAS7PhXcaXK5z4tw0IOWVXVHKf7xXibbPRwQVIyF4YUaoanmrkzUa0aU-oWXGdBsBmo4CIhj8jcY5YZFtZF7ynov_3a-8-dQNcfjc6_1U6bBw95bsP6C-oJhaXmX2fnAuVpcK0BjkQ3zoI7SGikTLGwclPJ1WsvTo2pX3HR6QCc1puvDjaO3gBA0mn_S6q3TL6mOqYDIeD3b6aklNbobHe1QSm1rRLO7I-j7B-qiAGb_gGLTRndBc4ZI-sWkwQGOkZeEugJukgspmWAmFYd821RXQ9M8egqCYsVM7FsEm_raKvSG2ehxFo7ZSVbLM\",\"e\": \"AQAB\" },{\"kty\":\"RSA\",\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}]}");

        BigInteger modulus = new BigInteger(
                "22128946737323913239210052479333027707901510060102775675830991813349418659538199300647898430584144500806059458278321518777044762899512296866600872394644380219013320495156971514431190023600729602211122577883306928327035481763181383360484196857466673122026840292263234856687762092039930273840883706411057986999291723263528956058054902470342623926525220419403492184749748080083440782860930153041629788053392850350190345701856884676367792841834106393147716901597512639433053628947682648446566660847625123370647049602729290059736582541200917525808306486312868092094709254446973240693245640735124383753810943940731642145971");
        BigInteger publicExponent = new BigInteger("65537");
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        BigInteger modulus2 = new BigInteger(
                "-5682458471133998388349435224633069349339468533284902336027705964449388702650944577143355769222747143645802928997396746788844516020279137866835783191591333722847996520065852710220990368127004199808401899736680560956431068787853232744544770599290862357208116339307372204787434279492353211428856678472586090071739438019744959023980640454937307928948909285462577350157199294652794553602056459172956409144930859767392952162694193223130644537748426311422152249961861449835863678305650703998634078098161038037616498189346650489296709705191330089861202606165927388552774443778601636463150652207936779357119888256103014675837");
        BigInteger publicExponent2 = new BigInteger("65537");
        PublicKey publicKey2 = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus2, publicExponent2));

        List<PublicKey> publicKeyList = Converter.getRsaPublicKeysByJwk(jwk);

        assertNotNull(publicKeyList);
        assertEquals(publicKeyList.size(), 2);
        assertEquals(publicKey, publicKeyList.get(0));
        assertEquals(publicKey2, publicKeyList.get(1));
    }

    @Test
    public void getRsaPublicKeyByPkcs8PemStringReturnsCorrectRsaPublicKeyObject() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pemString = "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqNyaO8jKmo/vfcFmxVNx\n"
                + "mJD4s+pJah9v/y7TxT1EGLLHZhAjZji7cZ+tyu5XDX6X9Mv3Cw5teQu9cdlTbdFp\n" + "rS9jRasnMlOfqI0V7jc7MOpa3n7AOeAYW9kFCL0qykKEs5B1f+F4zNAxp0hdE3eQ\n"
                + "KYCbCprXjHKF1CfH28C0Qk+GUtaRJbLaUybBoGvQ7vW/fdVUkuk3lOgnzF9dgrm0\n" + "8u11QLQpkF5glpC9ydiuWPNEKuOzTOGcgT3kA9XxliBLmuXO6OjDxxzzoDokMg82\n"
                + "rsQ9XQOE9E3MRF2THfeMyQW7lRO63DOPCM3OBboSlUJQxWFVlA+YbMMUU7G0LdFX\n" + "lQIDAQAB\n" + "-----END PUBLIC KEY-----\n";

        RSAPublicKey publicKey = Converter.getRsaPublicKeyByPemString(pemString);

        BigInteger modulus = new BigInteger(
                "21316818368993447071015504638669801307527791584419862690177839595942029205894278985540228412443487713781149000078791190623276463454823320959362260326199842987421361386139414049320560418755520845179985115136181677185147622508697723189907444611574225122510119509110186633493415018035262172045096131517158872141869399939837654786497010314012641458269735824601371910054201921752066689022132849085664346125596962587379664190262614011733894298373034667307278544652193891973668886039046311943231827345356203903687328889718549241623336004630871090544516461376300794799815319108967915139001745002800408170876902995920807876501");
        BigInteger publicExponent = new BigInteger("65537");

        RSAPublicKey expectedPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        assertEquals(expectedPublicKey, publicKey);
    }

    @Test
    public void getRsaPublicKeyByPkcs1PemStringReturnsCorrectRsaPublicKeyObject() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pemString = "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0uGtoAbxPPnkWcuT31D\n"
                + "VX6skQBLs+FdxpcrnPi3DQg5ZVdUcp/vFeJts9HBBUjIXhhRqhqeauTNRrRpT6hZ\n" + "cZ0GwGajgIiGPyNxjlhkW1kXvKei//dr7z51A1x+Nzr/VTpsHD3luw/oL6gmFpeZ\n"
                + "fZ+cC5WlwrQGORDfOgjtIaKRMsbByU8nVay9OjalfcdHpAJzWm68ONo7eAEDSaf9\n" + "LqrdMvqY6pgMh4PdvpqSU1uhsd7VBKbWtEs7sj6PsH6qIAZv+AYtNGd0Fzhkj6xa\n"
                + "TBAY6Rl4S6Am6SCymZYCYVh3zbVFdD0zx6CoJixUzsWwSb+toq9IbZ6HEWjtlJVs\n" + "swIDAQAB\n" + "-----END PUBLIC KEY-----";

        RSAPublicKey publicKey = Converter.getRsaPublicKeyByPemString(pemString);

        BigInteger modulus = new BigInteger(
                "22128946737323913239210052479333027707901510060102775675830991813349418659538199300647898430584144500806059458278321518777044762899512296866600872394644380219013320495156971514431190023600729602211122577883306928327035481763181383360484196857466673122026840292263234856687762092039930273840883706411057986999291723263528956058054902470342623926525220419403492184749748080083440782860930153041629788053392850350190345701856884676367792841834106393147716901597512639433053628947682648446566660847625123370647049602729290059736582541200917525808306486312868092094709254446973240693245640735124383753810943940731642145971");
        BigInteger publicExponent = new BigInteger("65537");

        RSAPublicKey expectedPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        assertEquals(expectedPublicKey, publicKey);
    }

    @Test
    public void getRsaPublicKeysByJwkWithIdWithTwoRsaJwkInputReturnsHashmapWithTwoRsaPublicKeyObjectsAndRelatedDescribingStrings()
            throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException {
        Object jwk = new JSONParser()
                .parse("{\"keys\":[{ \"kty\": \"RSA\",\"use\": \"sig\",\"n\": \"AK9LhraAG8Tz55FnLk99Q1V-rJEAS7PhXcaXK5z4tw0IOWVXVHKf7xXibbPRwQVIyF4YUaoanmrkzUa0aU-oWXGdBsBmo4CIhj8jcY5YZFtZF7ynov_3a-8-dQNcfjc6_1U6bBw95bsP6C-oJhaXmX2fnAuVpcK0BjkQ3zoI7SGikTLGwclPJ1WsvTo2pX3HR6QCc1puvDjaO3gBA0mn_S6q3TL6mOqYDIeD3b6aklNbobHe1QSm1rRLO7I-j7B-qiAGb_gGLTRndBc4ZI-sWkwQGOkZeEugJukgspmWAmFYd821RXQ9M8egqCYsVM7FsEm_raKvSG2ehxFo7ZSVbLM\","
                        + "\"e\": \"AQAB\" },{\"kty\":\"RSA\",\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
                        + "\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"},{\"kty\":\"EC\","
                        + "\"crv\":\"P-256\","
                        + "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                        + "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
                        + "\"use\":\"enc\"," + "\"kid\":\"1\"" + "}]}");

        BigInteger modulus = new BigInteger(
                "22128946737323913239210052479333027707901510060102775675830991813349418659538199300647898430584144500806059458278321518777044762899512296866600872394644380219013320495156971514431190023600729602211122577883306928327035481763181383360484196857466673122026840292263234856687762092039930273840883706411057986999291723263528956058054902470342623926525220419403492184749748080083440782860930153041629788053392850350190345701856884676367792841834106393147716901597512639433053628947682648446566660847625123370647049602729290059736582541200917525808306486312868092094709254446973240693245640735124383753810943940731642145971");
        BigInteger publicExponent = new BigInteger("65537");
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        BigInteger modulus2 = new BigInteger(
                "-5682458471133998388349435224633069349339468533284902336027705964449388702650944577143355769222747143645802928997396746788844516020279137866835783191591333722847996520065852710220990368127004199808401899736680560956431068787853232744544770599290862357208116339307372204787434279492353211428856678472586090071739438019744959023980640454937307928948909285462577350157199294652794553602056459172956409144930859767392952162694193223130644537748426311422152249961861449835863678305650703998634078098161038037616498189346650489296709705191330089861202606165927388552774443778601636463150652207936779357119888256103014675837");
        BigInteger publicExponent2 = new BigInteger("65537");
        PublicKey publicKey2 = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus2, publicExponent2));

        HashMap<String, PublicKey> publicKeyList = Converter.getRsaPublicKeysByJwkWithId(jwk);

        assertNotNull(publicKeyList);
        assertEquals(publicKeyList.size(), 2);
        assertEquals(publicKey, publicKeyList.get("#1_RSA_sig"));
        assertEquals(publicKey2, publicKeyList.get("#2_RSA_RS256_2011-04-29"));
    }

    @Test
    public void getECPublicKeyByJwkInputNotJSONObjcet() {
        Object input = new Object();
        assertNull(Converter.getECPublicKeyByJwk(input));
    }

    @Test
    public void getECPublicKeyByJwkInputIsJSONObjcetWithoutKty() {
        JSONObject input = new JSONObject();
        assertNull(Converter.getECPublicKeyByJwk(input));
    }

    @Test
    public void getECPublicKeyByJwkInputIsJSONObjcetWithKtyNotEC() throws ParseException {
        Object input = new JSONParser()
                .parse("{\"kty\": \"RSA\", \"use\": \"sig\", \"n\": \"AK9LhraAG8Tz55FnLk99Q1V-rJEAS7PhXcaXK5z4tw0IOWVXVHKf7xXibbPRwQVIyF4YUaoanmrkzUa0aU-oWXGdBsBmo4CIhj8jcY5YZFtZF7ynov_3a-8-dQNcfjc6_1U6bBw95bsP6C-oJhaXmX2fnAuVpcK0BjkQ3zoI7SGikTLGwclPJ1WsvTo2pX3HR6QCc1puvDjaO3gBA0mn_S6q3TL6mOqYDIeD3b6aklNbobHe1QSm1rRLO7I-j7B-qiAGb_gGLTRndBc4ZI-sWkwQGOkZeEugJukgspmWAmFYd821RXQ9M8egqCYsVM7FsEm_raKvSG2ehxFo7ZSVbLM\", \"e\": \"AQAB\"}");
        assertNull(Converter.getECPublicKeyByJwk(input));
    }

    @Test
    public void getECPublicKeyByJwkInputIsJSONObjcetWrongCurve() throws ParseException {
        Object input = new JSONParser()
                .parse("{\"kty\":\"EC\", \"crv\":\"P-257\", \"x\":\"_h70D5NdAGyh8-maXO-fzVfaZAYsyNQGcXelJII1DRw\", \"y\":\"jIAYcIcTcGaDX75BFF5pPRopo1lpRq3XpM4d31Wzaa0\", \"use\":\"enc\", \"kid\":\"1\"}");
        assertNull(Converter.getECPublicKeyByJwk(input));
    }

    @Test
    public void getECPublicKeyByJwkInputReturnsECPublicKeyObjects() throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchProviderException {
        // Object jwk = new
        // JSONParser().parse("{\"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", \"use\":\"enc\", \"kid\":\"1\"}");
        Object jwk = new JSONParser()
                .parse("{\"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"_h70D5NdAGyh8-maXO-fzVfaZAYsyNQGcXelJII1DRw\", \"y\":\"jIAYcIcTcGaDX75BFF5pPRopo1lpRq3XpM4d31Wzaa0\", \"use\":\"enc\", \"kid\":\"1\"}");

        BigInteger x = Base64.decodeInteger("_h70D5NdAGyh8-maXO-fzVfaZAYsyNQGcXelJII1DRw".getBytes());
        BigInteger y = Base64.decodeInteger("jIAYcIcTcGaDX75BFF5pPRopo1lpRq3XpM4d31Wzaa0".getBytes());
        ECFieldElement fex = new SecP256R1FieldElement(x);
        ECFieldElement fey = new SecP256R1FieldElement(y);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        ECPoint ecpublicKeyTest = new SecP256R1Point(ecParameterSpec.getCurve(), fex, fey);
        ECKeySpec ecpks = new ECPublicKeySpec(ecpublicKeyTest, ecParameterSpec);
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(ecpks);
        ECPublicKey publicKeyToTest = Converter.getECPublicKeyByJwk(jwk);
        assertEquals(publicKey, publicKeyToTest);
    }

    @Test
    public void getECPublicKeyByJwkInput() throws ParseException {
        Object jwk = new JSONParser().parse("{" + "\"enc\": \"A128CBC-HS256\"," + "\"alg\": \"ECDH-ES+A128KW\"," + "\"epk\": {" + "\"kty\": \"EC\","
                + "\"x\": \"acJ36kKjdhB3eE53fgpdO1QLj3206LKDwmHu1zp_vlg\"," + "\"y\": \"dWOKHC2CaCi_u8SVNPRZU0NkErgiSbeM4ZMUE65Stjs\","
                + "\"crv\": \"P-256\"}}");
        ECPublicKey publicKeyToTest = Converter.getECPublicKeyByJwk(jwk);
    }
}
