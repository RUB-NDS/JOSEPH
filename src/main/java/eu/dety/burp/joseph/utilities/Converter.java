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
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;


/**
 * Help functions to convert JSON Web Key to RSA PublicKey
 * @author Dennis Detering
 * @version 1.0
 */
public class Converter {
    private static final Logger loggerInstance = Logger.getInstance();

    /**
     * Get RSA PublicKey list by JWK JSON input
     * @param input JSON Web Key {@link JSONObject}
     * @return List of {@link PublicKey}
     */
    public static List<PublicKey> getRsaPublicKeysByJwk(final Object input) {
        List<PublicKey> keys = new ArrayList<>();

        if (!(input instanceof JSONObject)) return keys;

        JSONObject inputJsonObject = (JSONObject) input;

        // Multiple keys existent
        if (inputJsonObject.containsKey("keys")) {
            loggerInstance.log(Converter.class, "Key array found...", Logger.LogLevel.DEBUG);

            for (final Object value : (JSONArray) inputJsonObject.get("keys")) {
                JSONObject keyJson = (JSONObject) value;

                PublicKey key = getRsaPublicKeyByJwk(keyJson);

                if (key != null) keys.add(key);
            }
        } else {
            PublicKey key = getRsaPublicKeyByJwk(inputJsonObject);

            if (key != null) keys.add(key);
        }

        return keys;
    }

    /**
     * Get RSA PublicKey by JWK JSON input
     * @param input JSON Web Key {@link JSONObject}
     * @return {@link PublicKey} or null
     */
    private static PublicKey getRsaPublicKeyByJwk(JSONObject input) {
        if (!input.containsKey("kty")) return null;
        String kty = (String) input.get("kty");

        if (kty.equals("RSA")) return buildRsaPublicKeyByJwk(input);

        return null;
    }

    /**
     * Build RSA {@link PublicKey} from RSA JWK JSON object
     * @param input RSA JSON Web Key {@link JSONObject}
     * @return {@link PublicKey} or null
     */
    private static PublicKey buildRsaPublicKeyByJwk(JSONObject input) {
        try {
            BigInteger modulus = new BigInteger(Base64.decodeBase64(input.get("n").toString()));
            BigInteger publicExponent = new BigInteger(Base64.decodeBase64(input.get("e").toString()));

            loggerInstance.log(Converter.class, "RSA PublicKey values: N: " + modulus + " E: " + publicExponent, Logger.LogLevel.DEBUG);
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Build {@link RSAPublicKey} from PublicKey PEM string
     * @param pemInput PublicKey PEM string
     * @return {@link RSAPublicKey} or null
     */
    public static RSAPublicKey getRsaPublicKeyByPemString(String pemInput) {
        String pubKey = pemInput.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
        RSAPublicKey publicKey = null;

        try {
            byte[] keyBytes = Base64.decodeBase64(pubKey);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {
            loggerInstance.log(Converter.class, "Error during pem to RSAPublicKey conversion: " + e.getMessage(), Logger.LogLevel.ERROR);
        }

        return publicKey;
    }


}
