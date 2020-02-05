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

import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.*;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.*;

/**
 * Help functions to convert JSON Web Key to RSA or EC PublicKey
 *
 * @author Dennis Detering, Vincent Unsel
 * @version 1.1
 */
public class Converter {
    private static final Logger loggerInstance = Logger.getInstance();

    /**
     * Get RSA PublicKey list by JWK JSON input
     *
     * @param input
     *            JSON Web Key {@link JSONObject}
     * @return List of {@link PublicKey}
     */
    public static List<PublicKey> getRsaPublicKeysByJwk(final Object input) {
        List<PublicKey> keys = new ArrayList<>();

        if (!(input instanceof JSONObject))
            return keys;

        JSONObject inputJsonObject = (JSONObject) input;

        // Multiple keys existent
        if (inputJsonObject.containsKey("keys")) {
            loggerInstance.log(Converter.class, "Key array found...", Logger.LogLevel.DEBUG);

            for (final Object value : (JSONArray) inputJsonObject.get("keys")) {
                JSONObject keyJson = (JSONObject) value;

                PublicKey key = getRsaPublicKeyByJwk(keyJson);

                if (key != null)
                    keys.add(key);
            }
        } else {
            PublicKey key = getRsaPublicKeyByJwk(inputJsonObject);

            if (key != null)
                keys.add(key);
        }

        return keys;
    }

    /**
     * Get RSA PublicKey by PublicKey HashMap input. Create a dialog popup with a combobox to choose the correct JWK to use.
     *
     * @param publicKeys
     *            HashMap containing a PublicKey and related describing string
     * @return Selected {@link PublicKey}
     * @throws AttackPreparationFailedException
     */
    @SuppressWarnings("unchecked")
    public static PublicKey getRsaPublicKeyByJwkSelectionPanel(HashMap<String, PublicKey> publicKeys) throws AttackPreparationFailedException {
        // TODO: Move to other class?
        JPanel selectionPanel = new JPanel();
        selectionPanel.setLayout(new java.awt.GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;

        constraints.gridy = 0;
        selectionPanel.add(new JLabel("Multiple JWKs found. Please choose one:"), constraints);

        JComboBox jwkSetKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> jwkSetKeySelectionModel = new DefaultComboBoxModel<>();

        for (Map.Entry<String, PublicKey> publicKey : publicKeys.entrySet()) {
            jwkSetKeySelectionModel.addElement(publicKey.getKey());
        }

        jwkSetKeySelection.setModel(jwkSetKeySelectionModel);

        constraints.gridy = 1;
        selectionPanel.add(jwkSetKeySelection, constraints);

        int resultButton = JOptionPane.showConfirmDialog(null, selectionPanel, "Select JWK", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);

        if (resultButton == JOptionPane.CANCEL_OPTION) {
            throw new AttackPreparationFailedException("No JWK from JWK Set selected!");
        }

        loggerInstance.log(Converter.class, "Key selected: " + jwkSetKeySelection.getSelectedIndex(), Logger.LogLevel.DEBUG);
        return publicKeys.get(jwkSetKeySelection.getSelectedItem());
    }

    /**
     * Get RSA PublicKey list by JWK JSON input with an identifying string
     *
     * @param input
     *            JSON Web Key {@link JSONObject}
     * @return HashMap of {@link PublicKey} with identifying string as key
     */
    public static HashMap<String, PublicKey> getRsaPublicKeysByJwkWithId(final Object input) {
        HashMap<String, PublicKey> keys = new HashMap<>();

        if (!(input instanceof JSONObject))
            return keys;

        JSONObject inputJsonObject = (JSONObject) input;

        // Multiple keys existent
        if (inputJsonObject.containsKey("keys")) {
            loggerInstance.log(Converter.class, "Key array found...", Logger.LogLevel.DEBUG);

            int counter = 1;
            for (final Object value : (JSONArray) inputJsonObject.get("keys")) {
                JSONObject keyJson = (JSONObject) value;

                PublicKey key = getRsaPublicKeyByJwk(keyJson);

                String id = "#" + counter;

                if (keyJson.containsKey("kty"))
                    id += "_" + keyJson.get("kty");
                if (keyJson.containsKey("alg"))
                    id += "_" + keyJson.get("alg");
                if (keyJson.containsKey("use"))
                    id += "_" + keyJson.get("use");
                if (keyJson.containsKey("kid"))
                    id += "_" + keyJson.get("kid");

                if (key != null)
                    keys.put(id, key);
                counter++;
            }
        } else {
            PublicKey key = getRsaPublicKeyByJwk(inputJsonObject);

            if (key != null)
                keys.put("#1", key);
        }

        return keys;
    }

    /**
     * Get RSA PublicKey by JWK JSON input
     *
     * @param input
     *            JSON Web Key {@link JSONObject}
     * @return {@link PublicKey} or null
     */
    private static PublicKey getRsaPublicKeyByJwk(JSONObject input) {
        if (!input.containsKey("kty"))
            return null;
        String kty = (String) input.get("kty");

        if (kty.equals("RSA"))
            return buildRsaPublicKeyByJwk(input);

        return null;
    }

    /**
     * Build RSA {@link PublicKey} from RSA JWK JSON object
     *
     * @param input
     *            RSA JSON Web Key {@link JSONObject}
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
     *
     * @param pemInput
     *            PublicKey PEM string
     * @return {@link RSAPublicKey} or null
     */
    public static RSAPublicKey getRsaPublicKeyByPemString(String pemInput) {
        RSAPublicKey publicKey = null;

        String pubKey = pemInput.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");

        // PKCS8
        try {
            byte[] keyBytes = Base64.decodeBase64(pubKey);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {
        }

        // PKCS1
        try {
            byte[] keyBytes = Base64.decodeBase64(pubKey);
            keyBytes = Arrays.copyOfRange(keyBytes, 24, keyBytes.length);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {
        }

        return publicKey;
    }

    /**
     * Get EC PublicKey by JWK JSON input
     *
     * @param input
     *            JSON Web Key {@link Object}
     * @return {@link PublicKey} or null
     */
    public static ECPublicKey getECPublicKeyByJwk(Object input) {
        if (!(input instanceof JSONObject)) {
            loggerInstance.log(Converter.class, "Input not JSONObject.", Logger.LogLevel.ERROR);
            return null;
        }
        String kty;
        ECPublicKey result = null;
        JSONObject jsonInput = (JSONObject) input;
        if (jsonInput.containsKey("kty")) {
            kty = jsonInput.get("kty").toString();
            if (kty.equals("EC")) {
                result = buildECPublicKeyByJwk(jsonInput);
            }
        } else if (jsonInput.containsKey("epk")) {
            JSONObject innerJsonArray = (JSONObject) jsonInput.get("epk");
            kty = (String) innerJsonArray.get("kty");
            if (kty.equals("EC"))
                result = buildECPublicKeyByJwk(innerJsonArray);
        } else {
            loggerInstance.log(Converter.class, "JSONObject does not contain kty.", Logger.LogLevel.ERROR);
        }
        return result;
    }

    /**
     * Build EC {@link ECPublicKey} from EC JWK JSON object
     *
     * @param input
     *            EC JSON Web Key {@link JSONObject}
     * @return {@link ECPublicKey} or null
     */
    private static ECPublicKey buildECPublicKeyByJwk(JSONObject input) {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            String crv = input.get("crv").toString();
            BigInteger x = Base64.decodeInteger(input.get("x").toString().getBytes());
            BigInteger y = Base64.decodeInteger(input.get("y").toString().getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(crv);
            ECPoint ecPoint;

            switch (crv) {
                case "P-256": {
                    ECFieldElement fex = new SecP256R1FieldElement(x);
                    ECFieldElement fey = new SecP256R1FieldElement(y);
                    ecPoint = new SecP256R1Point(ecParameterSpec.getCurve(), fex, fey);
                    break;
                }
                case "P-384": {
                    ECFieldElement fex = new SecP384R1FieldElement(x);
                    ECFieldElement fey = new SecP384R1FieldElement(y);
                    ecPoint = new SecP384R1Point(ecParameterSpec.getCurve(), fex, fey);
                    break;
                }
                case "P-521": {
                    ECFieldElement fex = new SecP521R1FieldElement(x);
                    ECFieldElement fey = new SecP521R1FieldElement(y);
                    ecPoint = new SecP521R1Point(ecParameterSpec.getCurve(), fex, fey);
                    break;
                }
                default:
                    return null;
            }

            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            PublicKey result = keyFactory.generatePublic(ecPublicKeySpec);
            return (ECPublicKey) result;
        } catch (Exception e) {
            loggerInstance.log(Converter.class, "Failed building ECPublicKey from JWK: " + e.getMessage(), Logger.LogLevel.ERROR);
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Get EC {@link PublicKey} from EC PEM String
     *
     * @param pemString
     * @return {@link PublicKey} or null
     */
    public static PublicKey getECPublicKeyByPemString(String pemString) {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Reader reader = new StringReader(pemString);
        PemObject pemObject;
        try {
            pemObject = new PemReader(reader).readPemObject();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObject.getContent());
            return KeyFactory.getInstance("EC", "BC").generatePublic(keySpec);
        } catch (Exception e) {
            loggerInstance.log(Converter.class, "Failed building ECPublicKey from PEM: " + e.getMessage(), Logger.LogLevel.ERROR);
            e.printStackTrace();
        }
        return null;
    }
}
