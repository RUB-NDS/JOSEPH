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
package eu.dety.burp.joseph.attacks.BleichenbacherPkcs1;

import burp.*;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Jwk;
import eu.dety.burp.joseph.utilities.Logger;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.parser.JSONParser;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Bleichenbacher PKCS1 Attack Info
 * <p>
 * Class holding meta data for the Bleichenbacher RSA PKCS#1 v1.5 attack
 * and for preparing all necessary parameter for the actual attack.
 *
 * @author Dennis Detering
 * @version 1.0
 */
public class BleichenbacherPkcs1Info implements IAttackInfo {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    private Decoder joseDecoder = new Decoder();
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "bleichenbarcher_pkcs1";

    // Full name of the attack
    private static final String name = "Bleichenbacher RSA PKCS#1 v1.5";

    // Attack description
    private static final String description = "<html>The <em>Bleichenbacher RSA PKCS#1 v1.5</em> attack exploits a vulnerability where ...</html>";

    // List of types this attack is suitable for
    private static final List<String> suitableTypes = Arrays.asList("jwe");

    // Array of algorithms to test
    private static final String[] algorithms = {"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"};

    // Amount of requests needed
    private int amountRequests = 0;

    // Types of payload variation
    private enum payloadType {

    }

    // Hashmap of available payloads with a verbose name (including the payloadType)
    private static final HashMap<String, payloadType> payloads = new HashMap<String, payloadType>() {{
        for (payloadType payload : payloadType.values()) {
            put(String.format("Vector: %s   (0x%02X)", payload, payload.ordinal()), payload);
        }
    }};

    // List of prepared requests with payload info
    private List<BleichenbacherPkcs1AttackRequest> requests = new ArrayList<>();

    private JComboBox<String> publicKeySelection;
    private JTextArea publicKey;

    public BleichenbacherPkcs1Info(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public BleichenbacherPkcs1 prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        this.amountRequests = requests.size();
        return new BleichenbacherPkcs1(callbacks, this);
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public List<String> getSuitableTypes() {
        return suitableTypes;
    }

    @Override
    public int getAmountRequests() {
        return amountRequests;
    }

    @Override
    public boolean getExtraUI(JPanel extraPanel, GridBagConstraints constraints) {
        // Create combobox and textarea to add public key (in different formats)
        JLabel publicKeyLabel = new JLabel(bundle.getString("PUBKEY_FORMAT"));
        publicKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> publicKeySelectionListModel= new DefaultComboBoxModel<>();
        publicKey = new JTextArea(10, 50);
        publicKey.setLineWrap(true);

        publicKeySelectionListModel.addElement("PEM (String)");
        publicKeySelectionListModel.addElement("JWK (JSON)");

        publicKeySelection.setModel(publicKeySelectionListModel);

        constraints.gridy = 0;
        extraPanel.add(publicKeyLabel, constraints);

        constraints.gridy = 1;
        extraPanel.add(publicKeySelection, constraints);

        constraints.gridy = 2;
        extraPanel.add(publicKey, constraints);

        return true;
    }

    @Override
    public boolean isSuitable(String type, String algorithm) {
        return true;
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    @Override
    public List<BleichenbacherPkcs1AttackRequest> getRequests() {
        return this.requests;
    }

    @Override
    public HashMap<String, payloadType> getPayloadList() {
        return payloads;
    }

    @Override
    public HashMap<String, String> updateValuesByPayload(Enum payloadTypeId, String header, String payload) throws AttackPreparationFailedException {
        HashMap<String, String> result = new HashMap<>();

        return result;
    }

    private String generateSignature(String algorithm, byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            SecretKeySpec secret_key = new SecretKeySpec(key, algorithm);
            mac.init(secret_key);

            return joseDecoder.getEncoded(mac.doFinal(message));
        } catch (Exception e) {
            loggerInstance.log(getClass(), "Error during signature generation: " + e.getMessage(), Logger.LogLevel.ERROR);
            return "ERROR";
        }
    }

}
