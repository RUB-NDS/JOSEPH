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
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
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
     * Get RSA PublicKey by PublicKey HashMap input.
     * Create a dialog popup with a combobox to choose the correct JWK to use.
     * @param publicKeys HashMap containing a PublicKey and related describing string
     * @throws AttackPreparationFailedException
     * @return Selected {@link PublicKey}
     */
    public static PublicKey getRsaPublicKeyByJwkSelectionPanel(HashMap<String, PublicKey> publicKeys) throws AttackPreparationFailedException {
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
     * @param input JSON Web Key {@link JSONObject}
     * @return HashMap of {@link PublicKey} with identifying string as key
     */
    public static HashMap<String, PublicKey> getRsaPublicKeysByJwkWithId(final Object input) {
        HashMap<String, PublicKey> keys = new HashMap<>();

        if (!(input instanceof JSONObject)) return keys;

        JSONObject inputJsonObject = (JSONObject) input;

        // Multiple keys existent
        if (inputJsonObject.containsKey("keys")) {
            loggerInstance.log(Converter.class, "Key array found...", Logger.LogLevel.DEBUG);

            int counter = 1;
            for (final Object value : (JSONArray) inputJsonObject.get("keys")) {
                JSONObject keyJson = (JSONObject) value;

                PublicKey key = getRsaPublicKeyByJwk(keyJson);

                String id = "#" + counter;

                if (keyJson.containsKey("kty")) id += "_" + keyJson.get("kty");
                if (keyJson.containsKey("alg")) id += "_" + keyJson.get("alg");
                if (keyJson.containsKey("use")) id += "_" + keyJson.get("use");
                if (keyJson.containsKey("kid")) id += "_" + keyJson.get("kid");

                if (key != null) keys.put(id , key);
                counter++;
            }
        } else {
            PublicKey key = getRsaPublicKeyByJwk(inputJsonObject);

            if (key != null) keys.put("#1", key);
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
        RSAPublicKey publicKey = null;

        String pubKey = pemInput.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");

        // PKCS8
        try {
            byte[] keyBytes = Base64.decodeBase64(pubKey);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {}

        // PKCS1
        try {
            byte[] keyBytes = Base64.decodeBase64(pubKey);
            keyBytes = Arrays.copyOfRange(keyBytes, 24, keyBytes.length);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {}

        return publicKey;
    }


}
