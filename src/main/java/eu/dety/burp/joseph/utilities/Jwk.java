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
package eu.dety.burp.joseph.utilities;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;


/**
 * Help functions to convert JSON Web Key to RSA PublicKey
 * @author Dennis Detering
 * @version 1.0
 */
public class Jwk {
    private static final Logger loggerInstance = Logger.getInstance();

    /**
     * Get RSA PublicKey list by JWK JSON input
     * @param input JSON Web Key {@link JSONObject}
     * @return {@link PublicKey} or null
     */
    public static List<PublicKey> getRsaPublicKeys(final Object input) {
        List<PublicKey> keys = new ArrayList<>();

        if (!(input instanceof JSONObject)) return keys;

        JSONObject inputJsonObject = (JSONObject) input;

        // Multiple keys existent
        if (inputJsonObject.containsKey("keys")) {
            loggerInstance.log(Jwk.class, "Key array found...", Logger.LogLevel.DEBUG);

            for (final Object value : (JSONArray) inputJsonObject.get("keys")) {
                JSONObject keyJson = (JSONObject) value;

                PublicKey key = getRsaPublicKey(keyJson);

                if (key != null) keys.add(key);
            }
        } else {
            PublicKey key = getRsaPublicKey(inputJsonObject);

            if (key != null) keys.add(key);
        }

        return keys;
    }

    /**
     * Get RSA PublicKey by JWK JSON input
     * @param input JSON Web Key {@link JSONObject}
     * @return {@link PublicKey} or null
     */
    private static PublicKey getRsaPublicKey(JSONObject input) {
        if (!input.containsKey("kty")) return null;
        String kty = (String) input.get("kty");

        if (kty.equals("RSA")) return buildRsaPublicKey(input);

        return null;
    }

    /**
     * Build RSA {@link PublicKey} from RSA JWK JSON object
     * @param input RSA JSON Web Key {@link JSONObject}
     * @return {@link PublicKey} or null
     */
    private static PublicKey buildRsaPublicKey(JSONObject input) {
        try {
            BigInteger modulus = new BigInteger(Base64.decodeBase64(input.get("n").toString()));
            BigInteger publicExponent = new BigInteger(Base64.decodeBase64(input.get("e").toString()));

            loggerInstance.log(Jwk.class, "RSA PublicKey values: N: " + modulus + " E: " + publicExponent, Logger.LogLevel.DEBUG);
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (Exception e){
            return null;
        }
    }
}
